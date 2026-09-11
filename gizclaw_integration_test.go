// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

// GizClaw integration tests.
//
// These tests chain the fork's stream lifecycle and handshake fixes into
// end-to-end scenarios between two associations over an in-memory bridge,
// with packets dropped, held back, captured and replayed at the points where
// each fix matters. They live only on the gizclaw integration branch.

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/require"
)

const gizclawWait = 5 * time.Second

// gizclawLogs records error-level log messages so scenarios can assert that
// a replayed packet was handled quietly rather than as a protocol error.
type gizclawLogs struct {
	logging.LoggerFactory
	mu     sync.Mutex
	errors []string
}

func (f *gizclawLogs) NewLogger(scope string) logging.LeveledLogger {
	return &gizclawLogger{LeveledLogger: f.LoggerFactory.NewLogger(scope), logs: f}
}

func (f *gizclawLogs) errorCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.errors)
}

type gizclawLogger struct {
	logging.LeveledLogger
	logs *gizclawLogs
}

func (l *gizclawLogger) record(msg string) {
	l.logs.mu.Lock()
	l.logs.errors = append(l.logs.errors, msg)
	l.logs.mu.Unlock()
}

func (l *gizclawLogger) Error(msg string) {
	l.record(msg)
	l.LeveledLogger.Error(msg)
}

func (l *gizclawLogger) Errorf(format string, args ...any) {
	l.record(fmt.Sprintf(format, args...))
	l.LeveledLogger.Errorf(format, args...)
}

// gizclawHook inspects a packet written by one side and returns false to
// drop it. Hooks run with gizclawLink.mu held.
type gizclawHook func(pkt *packet) bool

type gizclawLink struct {
	t      *testing.T
	bridge *test.Bridge
	client *Association
	server *Association

	clientResets chan uint16
	serverResets chan uint16
	clientLogs   *gizclawLogs
	serverLogs   *gizclawLogs

	mu       sync.Mutex
	hooks    [2]gizclawHook
	injected map[string]int
	forward  [2][][]byte
}

type gizclawLinkConfig struct {
	interleaving bool
	clientOpts   []AssociationOption
	serverOpts   []AssociationOption
	// clientHook is installed before the handshake starts.
	clientHook gizclawHook
}

func newGizclawLink(t *testing.T, cfg gizclawLinkConfig) *gizclawLink {
	t.Helper()

	link := &gizclawLink{
		t:            t,
		bridge:       test.NewBridge(),
		clientResets: make(chan uint16, 1024),
		serverResets: make(chan uint16, 1024),
		injected:     map[string]int{},
		clientLogs:   &gizclawLogs{LoggerFactory: logging.NewDefaultLoggerFactory()},
		serverLogs:   &gizclawLogs{LoggerFactory: logging.NewDefaultLoggerFactory()},
	}
	link.hooks[0] = cfg.clientHook
	link.bridge.Filter(0, link.filter(0))
	link.bridge.Filter(1, link.filter(1))

	type result struct {
		assoc *Association
		err   error
	}
	clientCh := make(chan result, 1)
	serverCh := make(chan result, 1)
	go func() {
		opts := []ClientOption{
			WithName("gizclaw-client"),
			WithNetConn(link.bridge.GetConn0()),
			WithLoggerFactory(link.clientLogs),
			WithEnableInterleaving(cfg.interleaving),
		}
		for _, opt := range cfg.clientOpts {
			opts = append(opts, opt)
		}
		assoc, err := ClientWithOptions(opts...)
		clientCh <- result{assoc, err}
	}()
	go func() {
		opts := []ServerOption{
			WithName("gizclaw-server"),
			WithNetConn(link.bridge.GetConn1()),
			WithLoggerFactory(link.serverLogs),
			WithEnableInterleaving(cfg.interleaving),
		}
		for _, opt := range cfg.serverOpts {
			opts = append(opts, opt)
		}
		assoc, err := ServerWithOptions(opts...)
		serverCh <- result{assoc, err}
	}()

	deadline := time.Now().Add(gizclawWait)
	for link.client == nil || link.server == nil {
		require.True(t, time.Now().Before(deadline), "handshake timed out")
		link.tick()
		select {
		case res := <-clientCh:
			require.NoError(t, res.err)
			link.client = res.assoc
		case res := <-serverCh:
			require.NoError(t, res.err)
			link.server = res.assoc
		default:
		}
	}

	link.client.ackMode = ackModeNoDelay
	link.server.ackMode = ackModeNoDelay
	link.client.OnStreamResetComplete(func(id uint16) { link.clientResets <- id })
	link.server.OnStreamResetComplete(func(id uint16) { link.serverResets <- id })
	t.Cleanup(func() { closeAssociationPair(link.bridge, link.client, link.server) })

	return link
}

func (l *gizclawLink) filter(from int) func([]byte) bool {
	return func(raw []byte) bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		if n := l.injected[string(raw)]; n > 0 {
			l.injected[string(raw)] = n - 1

			return true
		}
		hook := l.hooks[from]
		if hook == nil {
			return true
		}
		pkt := &packet{}
		if pkt.unmarshal(true, raw) != nil {
			return true
		}

		return hook(pkt)
	}
}

// setHook replaces the hook for packets written by side from (0 = client).
func (l *gizclawLink) setHook(from int, hook gizclawHook) {
	l.mu.Lock()
	l.hooks[from] = hook
	l.mu.Unlock()
}

// locked runs fn with the hook lock held, for reading state hooks write.
func (l *gizclawLink) locked(fn func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fn()
}

// rawPacket serializes pkt for replay. It is called from hooks, which run on
// the bridge's writer goroutine, so it reports failure as nil rather than
// failing the test there.
func rawPacket(pkt *packet) []byte {
	raw, err := pkt.marshal(true)
	if err != nil {
		return nil
	}

	return raw
}

// forwardLater queues a rewritten packet for delivery on the next tick. The
// caller must hold l.mu (i.e. call it from a hook).
func (l *gizclawLink) forwardLater(from int, pkt *packet) {
	l.forward[from] = append(l.forward[from], rawPacket(pkt))
}

// inject delivers raw as if side from had written it, bypassing hooks.
func (l *gizclawLink) inject(from int, raw []byte) {
	l.mu.Lock()
	l.injected[string(raw)]++
	l.mu.Unlock()
	l.bridge.Push(raw, from)
}

func (l *gizclawLink) tick() {
	l.mu.Lock()
	forward := l.forward
	l.forward = [2][][]byte{}
	l.mu.Unlock()
	for from, raws := range forward {
		for _, raw := range raws {
			l.inject(from, raw)
		}
	}
	l.bridge.Tick()
	time.Sleep(time.Millisecond)
}

func (l *gizclawLink) await(what string, cond func() bool) {
	l.t.Helper()
	deadline := time.Now().Add(gizclawWait)
	for !cond() {
		require.True(l.t, time.Now().Before(deadline), "timed out waiting for %s", what)
		l.tick()
	}
}

// settle keeps the link running for a while without waiting on anything.
func (l *gizclawLink) settle(d time.Duration) {
	for end := time.Now().Add(d); time.Now().Before(end); {
		l.tick()
	}
}

type gizclawRead struct {
	data []byte
	err  error
}

func (l *gizclawLink) read(stream *Stream) ([]byte, error) {
	l.t.Helper()
	done := make(chan gizclawRead, 1)
	go func() {
		buf := make([]byte, 64*1024)
		n, _, err := stream.ReadSCTP(buf)
		done <- gizclawRead{data: buf[:n], err: err}
	}()
	var res gizclawRead
	l.await("stream read", func() bool {
		select {
		case res = <-done:
			return true
		default:
			return false
		}
	})

	return res.data, res.err
}

func (l *gizclawLink) write(stream *Stream, data []byte) {
	l.t.Helper()
	n, err := stream.WriteSCTP(data, PayloadTypeWebRTCBinary)
	require.NoError(l.t, err)
	require.Equal(l.t, len(data), n)
}

// openPair opens streamID on the client and accepts it on the server.
func (l *gizclawLink) openPair(streamID uint16) (*Stream, *Stream) {
	l.t.Helper()
	clientStream, err := l.client.OpenStream(streamID, PayloadTypeWebRTCBinary)
	require.NoError(l.t, err)
	hello := []byte("open")
	l.write(clientStream, hello)

	serverStream := l.accept()
	require.Equal(l.t, streamID, serverStream.StreamIdentifier())
	got, err := l.read(serverStream)
	require.NoError(l.t, err)
	require.Equal(l.t, hello, got)

	return clientStream, serverStream
}

// accept waits for the server to accept the next incoming stream.
func (l *gizclawLink) accept() *Stream {
	l.t.Helper()
	accepted := make(chan *Stream, 1)
	go func() {
		if stream, acceptErr := l.server.AcceptStream(); acceptErr == nil {
			accepted <- stream
		}
	}()
	var stream *Stream
	l.await("accept", func() bool {
		select {
		case stream = <-accepted:
			return true
		default:
			return false
		}
	})

	return stream
}

// exchange sends one message in each direction and checks delivery.
func (l *gizclawLink) exchange(clientStream, serverStream *Stream, tag string) {
	l.t.Helper()
	up := []byte("up:" + tag)
	l.write(clientStream, up)
	got, err := l.read(serverStream)
	require.NoError(l.t, err)
	require.Equal(l.t, up, got)

	down := []byte("down:" + tag)
	l.write(serverStream, down)
	got, err = l.read(clientStream)
	require.NoError(l.t, err)
	require.Equal(l.t, down, got)
}

// closeFromClient closes the client side, waits for the server to observe
// EOF, closes the server side and waits for both reset completions.
func (l *gizclawLink) closeFromClient(clientStream, serverStream *Stream) {
	l.t.Helper()
	require.NoError(l.t, clientStream.Close())
	_, err := l.read(serverStream)
	require.ErrorIs(l.t, err, io.EOF)
	require.NoError(l.t, serverStream.Close())
	id := clientStream.StreamIdentifier()
	require.Equal(l.t, id, l.awaitReset(l.serverResets, "server"))
	require.Equal(l.t, id, l.awaitReset(l.clientResets, "client"))
}

func (l *gizclawLink) awaitReset(events <-chan uint16, side string) uint16 {
	l.t.Helper()
	var id uint16
	l.await(side+" reset completion", func() bool {
		select {
		case id = <-events:
			return true
		default:
			return false
		}
	})

	return id
}

func (l *gizclawLink) requireNoResetEvents() {
	l.t.Helper()
	select {
	case id := <-l.clientResets:
		require.FailNowf(l.t, "unexpected client reset completion", "stream %d", id)
	case id := <-l.serverResets:
		require.FailNowf(l.t, "unexpected server reset completion", "stream %d", id)
	default:
	}
}

func onlySACK(pkt *packet) (*chunkSelectiveAck, []chunk) {
	var sack *chunkSelectiveAck
	var rest []chunk
	for _, c := range pkt.chunks {
		if s, ok := c.(*chunkSelectiveAck); ok {
			sack = s
		} else {
			rest = append(rest, c)
		}
	}

	return sack, rest
}

func withChunks(pkt *packet, chunks []chunk) *packet {
	return &packet{
		sourcePort:      pkt.sourcePort,
		destinationPort: pkt.destinationPort,
		verificationTag: pkt.verificationTag,
		chunks:          chunks,
	}
}

// TestGizClawStreamGenerationChain drives one stream ID through three
// generations on a single association:
//
//  1. negotiated stream limits are reported through Metadata;
//  2. generation 1 is closed while its last message is partially reliable
//     and loses its tail fragment, so the peer's reset is answered "In
//     progress" and only completes once (I-)FORWARD-TSN closes the gap;
//  3. both reset directions must finish before the ID is reused;
//  4. generation 2 reuses the ID and survives a replay of generation 1's
//     reset request;
//  5. generation 2 is closed while its SACKs are held back, and a SACK for
//     generation 2 data that arrives after generation 3 reused the ID must
//     not release generation 3's buffered bytes;
//  6. every reset completes exactly once per generation.
func TestGizClawStreamGenerationChain(t *testing.T) {
	for _, tc := range []struct {
		name         string
		interleaving bool
	}{
		{name: "DATA", interleaving: false},
		{name: "I-DATA", interleaving: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runStreamGenerationChain(t, tc.interleaving)
		})
	}
}

func runStreamGenerationChain(t *testing.T, interleaving bool) {
	t.Helper()
	const streamID = uint16(5)

	link := newGizclawLink(t, gizclawLinkConfig{
		interleaving: interleaving,
		clientOpts:   []AssociationOption{WithNumStreams(20, 30)},
		serverOpts:   []AssociationOption{WithNumStreams(25, 10)},
	})

	// 1. Negotiated limits: inbound = min(local inbound, peer outbound).
	clientMeta, ok := link.client.Metadata()
	require.True(t, ok)
	require.Equal(t, uint16(10), clientMeta.NumInboundStreams)
	require.Equal(t, uint16(25), clientMeta.NumOutboundStreams)
	serverMeta, ok := link.server.Metadata()
	require.True(t, ok)
	require.Equal(t, uint16(25), serverMeta.NumInboundStreams)
	require.Equal(t, uint16(10), serverMeta.NumOutboundStreams)

	gen1Client, gen1Server := link.openPair(streamID)
	link.exchange(gen1Client, gen1Server, "gen1")

	staleReset := closeWithAbandonedTail(t, link, gen1Client, gen1Server)
	link.requireNoResetEvents()

	// 4. Generation 2 reuses the ID; a replayed generation 1 reset request
	// must not reset it.
	gen2Client, gen2Server := link.openPair(streamID)
	require.NotSame(t, gen1Server, gen2Server)
	link.inject(0, staleReset)
	link.settle(100 * time.Millisecond)
	link.exchange(gen2Client, gen2Server, "gen2")
	link.requireNoResetEvents()

	closeWithDelayedSACK(t, link, gen2Client, gen2Server)

	link.requireNoResetEvents()
}

// closeWithAbandonedTail closes a generation whose last message loses its
// tail fragment, and returns the raw reset request the client sent for it.
func closeWithAbandonedTail( //nolint:cyclop
	t *testing.T,
	link *gizclawLink,
	clientStream, serverStream *Stream,
) []byte {
	t.Helper()
	streamID := clientStream.StreamIdentifier()
	link.client.rtoMgr.setRTO(100.0, true)
	clientStream.SetReliabilityParams(false, ReliabilityTypeRexmit, 0)

	var (
		tailTSN      *uint32
		resetRequest []byte
		inProgress   bool
		forwardSeen  bool
	)
	link.setHook(0, func(pkt *packet) bool {
		for _, c := range pkt.chunks {
			switch chk := c.(type) {
			case *chunkPayloadData:
				if chk.streamIdentifier == streamID && chk.endingFragment && !chk.beginningFragment && tailTSN == nil {
					tsn := chk.tsn
					tailTSN = &tsn
				}
				if tailTSN != nil && chk.tsn == *tailTSN {
					return false // lose every transmission of the tail
				}
			case *chunkForwardTSN, *chunkIForwardTSN:
				if !inProgress {
					return false // let the reset request arrive first
				}
				forwardSeen = true
			case *chunkReconfig:
				if _, ok := chk.paramA.(*paramOutgoingResetRequest); ok {
					if resetRequest != nil {
						return false // only FORWARD-TSN may complete the reset
					}
					resetRequest = rawPacket(pkt)
				}
			}
		}

		return true
	})
	link.setHook(1, func(pkt *packet) bool {
		for _, c := range pkt.chunks {
			if chk, ok := c.(*chunkReconfig); ok {
				if resp, ok := chk.paramA.(*paramReconfigResponse); ok && resp.result == reconfigResultInProgress {
					inProgress = true
				}
			}
		}

		return true
	})

	link.write(clientStream, bytes.Repeat([]byte{0xab}, 2000))
	link.await("tail fragment", func() (sent bool) {
		link.locked(func() { sent = tailTSN != nil })

		return sent
	})
	link.closeFromClient(clientStream, serverStream)
	link.locked(func() {
		require.True(t, inProgress, "reset was not answered in progress")
		require.True(t, forwardSeen, "gap was not closed by forward TSN")
		require.NotNil(t, resetRequest)
	})
	link.setHook(0, nil)
	link.setHook(1, nil)
	clientStream.SetReliabilityParams(false, ReliabilityTypeReliable, 0)

	return resetRequest
}

// closeWithDelayedSACK closes a generation while the server's SACKs are held
// back, reuses the ID, then delivers the old SACK and checks that the new
// generation's buffered amount is untouched.
func closeWithDelayedSACK(t *testing.T, link *gizclawLink, clientStream, serverStream *Stream) {
	t.Helper()
	streamID := clientStream.StreamIdentifier()

	var held [][]byte
	link.setHook(1, func(pkt *packet) bool {
		sack, rest := onlySACK(pkt)
		if sack == nil {
			return true
		}
		held = append(held, rawPacket(withChunks(pkt, []chunk{sack})))
		if len(rest) > 0 {
			link.forwardLater(1, withChunks(pkt, rest))
		}

		return false
	})

	last := []byte("gen2 last message")
	link.write(clientStream, last)
	got, err := link.read(serverStream)
	require.NoError(t, err)
	require.Equal(t, last, got)
	link.closeFromClient(clientStream, serverStream)

	var gen2SACK []byte
	link.locked(func() {
		require.NotEmpty(t, held, "no SACK was held back")
		gen2SACK = held[len(held)-1]
	})

	gen3Client, err := link.client.OpenStream(streamID, PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	require.NotSame(t, clientStream, gen3Client)
	payload := bytes.Repeat([]byte{0xcd}, 4*len(last))
	link.write(gen3Client, payload)
	require.Equal(t, uint64(len(payload)), gen3Client.BufferedAmount())

	link.inject(1, gen2SACK)
	link.settle(50 * time.Millisecond)
	require.Equal(t, uint64(len(payload)), gen3Client.BufferedAmount(),
		"a delayed SACK for the previous generation released bytes of the new one")

	link.setHook(1, nil)
	gen3Server := link.accept()
	got, err = link.read(gen3Server)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	link.await("generation 3 acknowledged", func() bool { return gen3Client.BufferedAmount() == 0 })

	link.exchange(gen3Client, gen3Server, "gen3")
	link.closeFromClient(gen3Client, gen3Server)
}

// TestGizClawStreamChurn opens more streams than fit in a single reset
// request, closes them all from both sides at once and reuses every ID. It
// checks that outgoing reset requests stay serialized (one in flight), every
// reset completes exactly once, and the WFQ scheduler drops per-stream state.
func TestGizClawStreamChurn(t *testing.T) { //nolint:cyclop
	const numStreams = 300 // more than one reset request batch
	link := newGizclawLink(t, gizclawLinkConfig{interleaving: true})

	// Track outstanding reset requests per direction.
	var (
		outstanding [2]map[uint32]bool
		overlap     bool
	)
	outstanding[0] = map[uint32]bool{}
	outstanding[1] = map[uint32]bool{}
	trackResets := func(from int) gizclawHook {
		return func(pkt *packet) bool {
			for _, c := range pkt.chunks {
				chk, ok := c.(*chunkReconfig)
				if !ok {
					continue
				}
				for _, par := range []param{chk.paramA, chk.paramB} {
					switch p := par.(type) {
					case *paramOutgoingResetRequest:
						outstanding[from][p.reconfigRequestSequenceNumber] = true
						if len(outstanding[from]) > 1 {
							overlap = true
						}
					case *paramReconfigResponse:
						if p.result != reconfigResultInProgress {
							delete(outstanding[1-from], p.reconfigResponseSequenceNumber)
						}
					}
				}
			}

			return true
		}
	}
	link.setHook(0, trackResets(0))
	link.setHook(1, trackResets(1))

	for round := range 2 {
		clientStreams := make([]*Stream, numStreams)
		serverStreams := make([]*Stream, numStreams)
		for i := range clientStreams {
			clientStreams[i], serverStreams[i] = link.openPair(uint16(i))
		}
		for i := range clientStreams {
			require.NoError(t, clientStreams[i].Close())
			require.NoError(t, serverStreams[i].Close())
		}

		for _, side := range []struct {
			name   string
			events chan uint16
		}{{"client", link.clientResets}, {"server", link.serverResets}} {
			seen := map[uint16]bool{}
			for range numStreams {
				id := link.awaitReset(side.events, side.name)
				require.False(t, seen[id], "round %d: %s reset for stream %d completed twice", round, side.name, id)
				seen[id] = true
			}
		}
		link.settle(50 * time.Millisecond)
		link.requireNoResetEvents()

		link.client.lock.RLock()
		require.Empty(t, link.client.streams)
		policy, ok := link.client.pendingQueue.policy.(*interleavingStreamSchedulerPolicy)
		require.True(t, ok)
		wfq, ok := policy.scheduler.(*weightedFairQueueingPendingQueuePolicy)
		require.True(t, ok)
		require.Empty(t, wfq.streamFinish, "WFQ kept finish state for idle streams")
		link.client.lock.RUnlock()
	}

	link.locked(func() {
		require.False(t, overlap, "more than one outgoing reset request was in flight")
	})
}

// TestGizClawHandshakeRecovery loses the first INITs, checks that the
// handshake-specific RTO cap bounds the retry delay, then replays the INIT
// after the association is established and checks that it is ignored
// quietly and the association keeps working through a stream lifecycle.
func TestGizClawHandshakeRecovery(t *testing.T) {
	const handshakeRTOMax = 100.0
	var (
		inits    int
		lastInit []byte
	)
	start := time.Now()
	link := newGizclawLink(t, gizclawLinkConfig{
		interleaving: true,
		clientOpts:   []AssociationOption{WithHandshakeRTOMax(handshakeRTOMax)},
		clientHook: func(pkt *packet) bool {
			for _, c := range pkt.chunks {
				if _, ok := c.(*chunkInit); ok {
					inits++
					if inits <= 2 {
						return false
					}
					lastInit = rawPacket(pkt)
				}
			}

			return true
		},
	})
	elapsed := time.Since(start)
	// With the default 1s initial RTO, two lost INITs would cost at least 3s.
	require.Less(t, elapsed, 2*time.Second, "handshake retries were not capped by the handshake RTO max")
	link.locked(func() {
		require.Equal(t, 3, inits)
		require.NotNil(t, lastInit)
	})
	link.setHook(0, nil)

	// A delayed INIT from the handshake that established the association
	// belongs to it: it must be ignored, not handled as an unexpected INIT.
	serverErrors := link.serverLogs.errorCount()
	link.inject(0, lastInit)
	link.settle(100 * time.Millisecond)
	require.Equal(t, established, link.server.getState())
	require.Equal(t, established, link.client.getState())
	require.Equal(t, serverErrors, link.serverLogs.errorCount(), "duplicate INIT was handled as a protocol error")

	const streamID = uint16(1)
	clientStream, serverStream := link.openPair(streamID)
	link.exchange(clientStream, serverStream, "after duplicate init")
	link.closeFromClient(clientStream, serverStream)
	clientStream, serverStream = link.openPair(streamID)
	link.exchange(clientStream, serverStream, "reused")
}

// TestGizClawStreamBurstBacklog opens a burst of streams while the server is
// not accepting, checks that every stream's DATA is acknowledged without
// T3-rtx, then closes them all from both sides and repeats the burst on the
// same stream IDs, so queued-but-unaccepted streams are exercised together
// with serialized resets and stream ID reuse.
func TestGizClawStreamBurstBacklog(t *testing.T) {
	const numStreams = 200 // far beyond the former 16-stream accept backlog
	link := newGizclawLink(t, gizclawLinkConfig{interleaving: true})
	message := func(round int, id uint16) []byte { return fmt.Appendf(nil, "round %d stream %d", round, id) }

	for round := range 2 {
		start := time.Now()
		clientStreams := make([]*Stream, numStreams)
		for id := range uint16(numStreams) {
			stream, err := link.client.OpenStream(id, PayloadTypeWebRTCBinary)
			require.NoError(t, err)
			link.write(stream, message(round, id))
			clientStreams[id] = stream
		}
		link.await("burst acknowledged without accepting", func() bool { return link.client.BufferedAmount() == 0 })
		require.Less(t, time.Since(start), time.Second, "round %d: burst needed T3-rtx", round)

		serverStreams := make([]*Stream, numStreams)
		for range numStreams {
			stream := link.accept()
			got, err := link.read(stream)
			require.NoError(t, err)
			require.Equal(t, message(round, stream.StreamIdentifier()), got)
			serverStreams[stream.StreamIdentifier()] = stream
		}

		for id := range clientStreams {
			require.NoError(t, clientStreams[id].Close())
			require.NoError(t, serverStreams[id].Close())
		}
		for _, side := range []struct {
			name   string
			events chan uint16
		}{{"client", link.clientResets}, {"server", link.serverResets}} {
			seen := map[uint16]bool{}
			for range numStreams {
				id := link.awaitReset(side.events, side.name)
				require.False(t, seen[id], "round %d: %s reset for stream %d completed twice", round, side.name, id)
				seen[id] = true
			}
		}
	}
	require.Zero(t, link.client.stats.getNumT3Timeouts(), "new streams must not wait for T3-rtx")
	link.requireNoResetEvents()
}

// TestGizClawDCEPStyleBurst reproduces how pion-webrtc opens DataChannels:
// the client opens a burst of streams and sends a DCEP OPEN on each, while
// the server runs a single accept loop that reads each OPEN and replies with
// a DCEP ACK. Writing the ACK needs the association lock the read loop holds
// while it creates streams, and the application does some work per channel
// (modeled as acceptWork), so the accept loop falls behind a burst that
// arrives in a few packets. Every channel must still open promptly, without
// waiting for any retransmission, and the accept loop must never deadlock
// with the read loop (pion/sctp#30).
func TestGizClawDCEPStyleBurst(t *testing.T) {
	const (
		numChannels = 150
		acceptWork  = 2 * time.Millisecond
	)
	dcepOpen := []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	dcepAck := []byte{0x02}
	link := newGizclawLink(t, gizclawLinkConfig{interleaving: true})

	// Server: serial accept loop, as in pion-webrtc's SCTPTransport.
	acceptLoopDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		for range numChannels {
			stream, err := link.server.AcceptStream()
			if err != nil {
				acceptLoopDone <- err

				return
			}
			_, ppi, err := stream.ReadSCTP(buf)
			if err != nil || ppi != PayloadTypeWebRTCDCEP {
				acceptLoopDone <- fmt.Errorf("stream %d: read OPEN: ppi=%v err=%w", stream.StreamIdentifier(), ppi, err)

				return
			}
			time.Sleep(acceptWork) // create the DataChannel, run callbacks
			if _, err = stream.WriteSCTP(dcepAck, PayloadTypeWebRTCDCEP); err != nil {
				acceptLoopDone <- err

				return
			}
		}
		acceptLoopDone <- nil
	}()

	start := time.Now()
	channels := make([]*Stream, numChannels)
	for id := range uint16(numChannels) {
		stream, err := link.client.OpenStream(id, PayloadTypeWebRTCDCEP)
		require.NoError(t, err)
		n, err := stream.WriteSCTP(dcepOpen, PayloadTypeWebRTCDCEP)
		require.NoError(t, err)
		require.Equal(t, len(dcepOpen), n)
		channels[id] = stream
	}
	for _, stream := range channels {
		got, err := link.read(stream)
		require.NoError(t, err)
		require.Equal(t, dcepAck, got, "stream %d", stream.StreamIdentifier())
	}
	elapsed := time.Since(start)

	var loopErr error
	link.await("accept loop", func() bool {
		select {
		case loopErr = <-acceptLoopDone:
			return true
		default:
			return false
		}
	})
	require.NoError(t, loopErr)
	require.Zero(t, link.client.stats.getNumT3Timeouts(), "channel opens must not wait for T3-rtx")
	// Dropped opens are recovered by retransmission after roughly an RTO.
	require.Less(t, elapsed, time.Second, "channel opens should finish well within the 1s initial RTO")
}

// TestGizClawClosedStreamDiscardsBacklog closes a stream on the receiving
// side without reading it while the peer keeps sending more than the receive
// window on it, like a WebRTC data channel closed without being drained. The
// unread data must not hold the association's receive window: it is dropped,
// the window reopens and other streams keep working. The peer's reset then
// ends the stream, both reset directions complete, and a new generation on
// the same stream ID delivers its data normally.
func TestGizClawClosedStreamDiscardsBacklog(t *testing.T) {
	for _, tc := range []struct {
		name         string
		interleaving bool
	}{
		{name: "DATA", interleaving: false},
		{name: "I-DATA", interleaving: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runClosedStreamDiscardsBacklog(t, tc.interleaving)
		})
	}
}

func runClosedStreamDiscardsBacklog(t *testing.T, interleaving bool) {
	t.Helper()
	const (
		receiveBuffer = 16 * 1024
		chunkSize     = 8 * 1024
		closedID      = uint16(1)
		otherID       = uint16(2)
	)
	link := newGizclawLink(t, gizclawLinkConfig{
		interleaving: interleaving,
		serverOpts: []AssociationOption{
			WithMaxReceiveBufferSize(receiveBuffer),
			WithDiscardInboundAfterClose(true),
		},
	})
	serverWindow := func() uint32 {
		link.server.lock.RLock()
		defer link.server.lock.RUnlock()

		return link.server.getMyReceiverWindowCredit()
	}

	closedClient, closedServer := link.openPair(closedID)
	otherClient, otherServer := link.openPair(otherID)

	// The peer keeps sending twice the receive window on a stream the server
	// never reads.
	chunk := bytes.Repeat([]byte{'x'}, chunkSize)
	for range 4 {
		link.write(closedClient, chunk)
	}
	link.await("receive window to fill", func() bool { return serverWindow() < chunkSize })

	require.NoError(t, closedServer.Close())
	link.await("backlog of the closed stream to drain", func() bool {
		link.client.lock.RLock()
		defer link.client.lock.RUnlock()

		return link.client.pendingQueue.size() == 0 && link.client.inflightQueue.size() == 0
	})
	link.await("receive window to reopen", func() bool { return serverWindow() == receiveBuffer })
	link.exchange(otherClient, otherServer, "while closed stream drains")

	// The peer's reset ends the closed stream, and both directions complete.
	require.NoError(t, closedClient.Close())
	_, err := link.read(closedServer)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, closedID, link.awaitReset(link.serverResets, "server"))
	require.Equal(t, closedID, link.awaitReset(link.clientResets, "client"))

	// A new generation on the same ID must not inherit the discard state.
	reusedClient, reusedServer := link.openPair(closedID)
	link.write(reusedClient, chunk)
	got, err := link.read(reusedServer)
	require.NoError(t, err)
	require.Equal(t, chunk, got)
	link.exchange(reusedClient, reusedServer, "reused")
	link.exchange(otherClient, otherServer, "after reuse")
	require.Equal(t, uint32(receiveBuffer), serverWindow())
	link.requireNoResetEvents()
}
