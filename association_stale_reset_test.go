// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A retransmitted reset request that was already answered is answered again
// without resetting a stream that has since reused the identifier, and an
// out-of-order request is rejected.
func TestStreamResetRetransmissionDoesNotResetReusedStream(t *testing.T) {
	const (
		streamID       = uint16(7)
		firstSequence  = uint32(101)
		secondSequence = firstSequence + 1
	)
	assoc := createTestAssociation(t, Config{})
	t.Cleanup(func() {
		assoc.closeAllTimers()
		assoc.closeWriteLoopOnce.Do(func() { close(assoc.closeWriteLoopCh) })
	})
	assoc.setState(established)
	assoc.payloadQueue.init(100)
	assoc.peerNextRSN = firstSequence
	oldStream := assoc.createStream(streamID, false)
	require.NotNil(t, oldStream)

	completed := make(chan uint16, 2)
	assoc.OnStreamResetComplete(func(id uint16) {
		completed <- id
	})

	assoc.lock.Lock()
	assoc.completeStreamResetDirection(streamID, streamResetOutbound)
	response, err := assoc.handleReconfigParam(&paramOutgoingResetRequest{
		reconfigRequestSequenceNumber: firstSequence,
		senderLastTSN:                 100,
		streamIdentifiers:             []uint16{streamID},
	})
	assoc.lock.Unlock()
	require.NoError(t, err)
	require.Equal(t, reconfigResultSuccessPerformed, resetResponseResult(t, response))
	require.Equal(t, streamID, <-completed)

	newStream := assoc.createStream(streamID, false)
	require.NotNil(t, newStream)

	assoc.lock.Lock()
	response, err = assoc.handleReconfigParam(&paramOutgoingResetRequest{
		reconfigRequestSequenceNumber: firstSequence,
		senderLastTSN:                 100,
		streamIdentifiers:             []uint16{streamID},
	})
	assoc.lock.Unlock()
	require.NoError(t, err)
	require.Equal(t, reconfigResultSuccessPerformed, resetResponseResult(t, response))
	assert.Same(t, newStream, assoc.streams[streamID])

	assoc.lock.Lock()
	response, err = assoc.handleReconfigParam(&paramOutgoingResetRequest{
		reconfigRequestSequenceNumber: secondSequence,
		senderLastTSN:                 100,
	})
	assoc.lock.Unlock()
	require.NoError(t, err)
	require.Equal(t, reconfigResultSuccessPerformed, resetResponseResult(t, response))

	assoc.lock.Lock()
	response, err = assoc.handleReconfigParam(&paramOutgoingResetRequest{
		reconfigRequestSequenceNumber: firstSequence,
		senderLastTSN:                 100,
		streamIdentifiers:             []uint16{streamID},
	})
	assoc.lock.Unlock()
	require.NoError(t, err)
	require.Equal(t, reconfigResultErrorBadSequenceNumber, resetResponseResult(t, response))
	assert.Same(t, newStream, assoc.streams[streamID])

	select {
	case id := <-completed:
		require.FailNowf(t, "reset completion fired twice", "stream %d", id)
	default:
	}
}

// A retransmitted request that is still pending is re-evaluated instead of
// replaying the cached "In progress" response.
func TestStreamResetRetransmissionReevaluatesPendingRequest(t *testing.T) {
	const (
		streamID = uint16(7)
		sequence = uint32(101)
	)
	assoc := createTestAssociation(t, Config{})
	t.Cleanup(func() {
		assoc.closeAllTimers()
		assoc.closeWriteLoopOnce.Do(func() { close(assoc.closeWriteLoopCh) })
	})
	assoc.setState(established)
	assoc.payloadQueue.init(100)
	assoc.peerNextRSN = sequence
	stream := assoc.createStream(streamID, false)
	require.NotNil(t, stream)

	request := func() *paramOutgoingResetRequest {
		return &paramOutgoingResetRequest{
			reconfigRequestSequenceNumber: sequence,
			senderLastTSN:                 101,
			streamIdentifiers:             []uint16{streamID},
		}
	}

	assoc.lock.Lock()
	response, err := assoc.handleReconfigParam(request())
	assoc.lock.Unlock()
	require.NoError(t, err)
	require.Equal(t, reconfigResultInProgress, resetResponseResult(t, response))

	// The gap is closed without DATA (e.g. by FORWARD-TSN) and without the
	// pending request having been re-checked; the retransmission must
	// re-evaluate it rather than replay the cached "In progress".
	assoc.payloadQueue.advanceCumulativeTSN(101)

	assoc.lock.Lock()
	response, err = assoc.handleReconfigParam(request())
	assoc.lock.Unlock()
	require.NoError(t, err)
	require.Equal(t, reconfigResultSuccessPerformed, resetResponseResult(t, response))
	assert.NotContains(t, assoc.streams, streamID)
	assert.Empty(t, assoc.reconfigRequests)

	_, _, err = stream.ReadSCTP(make([]byte, 16))
	require.ErrorIs(t, err, io.EOF)
}

// A late response to our own reset request must not reset the counters of a
// stream that has since reused the identifier.
func TestLateStreamResetResponseKeepsReusedStreamCounters(t *testing.T) {
	const (
		si  uint16 = 1
		rsn uint32 = 2
	)
	assoc := createTestAssociation(t, Config{})
	t.Cleanup(func() {
		assoc.closeAllTimers()
		assoc.closeWriteLoopOnce.Do(func() { close(assoc.closeWriteLoopCh) })
	})
	assoc.setState(established)

	// The old generation was reset by the peer and removed, then closed,
	// which requested the outgoing reset that is answered below.
	assoc.reconfigs[rsn] = &chunkReconfig{
		paramA: &paramOutgoingResetRequest{
			reconfigRequestSequenceNumber: rsn,
			streamIdentifiers:             []uint16{si},
		},
	}

	// The peer reused the identifier before the answer arrived, and the
	// new generation has already sent a message.
	reopened := assoc.createStream(si, false)
	require.NotNil(t, reopened)
	reopened.sequenceNumber = 1
	reopened.nextOrderedMID = 1
	reopened.nextUnorderedMID = 1

	assoc.lock.Lock()
	_, err := assoc.handleReconfigParam(&paramReconfigResponse{
		reconfigResponseSequenceNumber: rsn,
		result:                         reconfigResultSuccessPerformed,
	})
	assoc.lock.Unlock()
	require.NoError(t, err)
	assert.Empty(t, assoc.reconfigs)

	reopened.lock.RLock()
	defer reopened.lock.RUnlock()
	assert.Equal(t, uint16(1), reopened.sequenceNumber, "reopened outbound SSN must not be reset")
	assert.Equal(t, uint32(1), reopened.nextOrderedMID, "reopened ordered MID must not be reset")
	assert.Equal(t, uint32(1), reopened.nextUnorderedMID, "reopened unordered MID must not be reset")
}

func TestLateStreamResetResponseKeepsReusedStreamDeliverable(t *testing.T) {
	for _, interleaving := range []bool{false, true} {
		t.Run(fmt.Sprintf("interleaving=%t", interleaving), func(t *testing.T) {
			testLateStreamResetResponseKeepsReusedStreamDeliverable(t, interleaving)
		})
	}
}

func testLateStreamResetResponseKeepsReusedStreamDeliverable(t *testing.T, interleaving bool) { //nolint:cyclop
	t.Helper()
	lim := test.TimeOut(10 * time.Second)
	defer lim.Stop()

	const streamID = uint16(1)
	bridge := test.NewBridge()
	client, server, err := createNewAssociationPairWithInterleaving(
		bridge, ackModeNoDelay, 0, interleaving, interleaving,
	)
	require.NoError(t, err)
	clientStream, serverStream, err := establishSessionPair(bridge, client, server, streamID)
	require.NoError(t, err)
	server.rtoMgr.setRTO(100.0, true)

	// Client -> server: hold back every RE-CONFIG response until released.
	var released atomic.Bool
	bridge.Filter(0, func(raw []byte) bool {
		pkt := &packet{}
		if released.Load() || pkt.unmarshal(true, raw) != nil {
			return true
		}
		for _, c := range pkt.chunks {
			if chk, ok := c.(*chunkReconfig); ok {
				if _, ok := chk.paramA.(*paramReconfigResponse); ok {
					return false
				}
			}
		}

		return true
	})

	clientCompleted := make(chan streamResetEvent, 1)
	client.OnStreamResetComplete(func(id uint16) {
		clientCompleted <- streamResetEvent{id: id}
	})

	readErr := func(s *Stream) (string, error) {
		t.Helper()
		type result struct {
			msg string
			err error
		}
		results := make(chan result, 1)
		go func() {
			buf := make([]byte, 64)
			n, _, rerr := s.ReadSCTP(buf)
			results <- result{msg: string(buf[:n]), err: rerr}
		}()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			bridge.Process()
			select {
			case res := <-results:
				return res.msg, res.err
			default:
				time.Sleep(time.Millisecond)
			}
		}
		require.FailNow(t, "message was never delivered")

		return "", nil
	}
	read := func(s *Stream) string {
		t.Helper()
		msg, rerr := readErr(s)
		require.NoError(t, rerr)

		return msg
	}

	// The client closes; the server sees the reset and closes too. The
	// client answers the server's reset and so sees both directions
	// complete, but its answer does not reach the server yet.
	require.NoError(t, clientStream.Close())
	_, err = readErr(serverStream)
	require.ErrorIs(t, err, io.EOF)
	require.NoError(t, serverStream.Close())
	require.Equal(t, streamResetEvent{id: streamID}, waitForResetEvent(t, bridge, clientCompleted))

	// The client reuses the identifier at once and the server replies.
	reusedClient, err := client.OpenStream(streamID, PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	_, err = reusedClient.WriteSCTP([]byte("request"), PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	flushBuffers(bridge, client, server)
	reusedServer, err := server.AcceptStream()
	require.NoError(t, err)
	require.Equal(t, "request", read(reusedServer))
	_, err = reusedServer.WriteSCTP([]byte("reply-1"), PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	require.Equal(t, "reply-1", read(reusedClient))

	// Now let the server's retransmitted reset request be answered.
	released.Store(true)
	require.Eventually(t, func() bool {
		bridge.Process()
		server.lock.RLock()
		defer server.lock.RUnlock()

		return len(server.reconfigs) == 0
	}, 5*time.Second, 10*time.Millisecond, "server reset request was never answered")

	_, err = reusedServer.WriteSCTP([]byte("reply-2"), PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	require.Equal(t, "reply-2", read(reusedClient))

	closeAssociationPair(bridge, client, server)
}
