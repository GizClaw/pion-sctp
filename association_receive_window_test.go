// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/require"
)

// newReceiveWindowTestAssoc returns an established association with a 2000
// byte receive buffer that expects the peer's DATA to start at TSN 100.
func newReceiveWindowTestAssoc(t *testing.T) *Association {
	t.Helper()

	assoc := createTestAssociation(t, Config{MaxReceiveBufferSize: 2000})
	t.Cleanup(func() {
		assoc.closeAllTimers()
		assoc.closeWriteLoopOnce.Do(func() { close(assoc.closeWriteLoopCh) })
	})
	assoc.setState(established)
	assoc.payloadQueue.init(99)

	return assoc
}

// receiveWindowTestChunk returns a 1000 byte DATA chunk of the first ordered
// message on stream si.
func receiveWindowTestChunk(tsn uint32, si uint16, first, last bool) *chunkPayloadData {
	return &chunkPayloadData{
		tsn:               tsn,
		streamIdentifier:  si,
		beginningFragment: first,
		endingFragment:    last,
		payloadType:       PayloadTypeWebRTCBinary,
		userData:          make([]byte, 1000),
	}
}

func TestAssocReceiveWindowFullOfIncompleteMessages(t *testing.T) {
	t.Run("accepts in-sequence DATA while nothing is readable", func(t *testing.T) {
		assoc := newReceiveWindowTestAssoc(t)
		assoc.lock.Lock()
		defer assoc.lock.Unlock()

		stream1 := assoc.getOrCreateStream(1, false, PayloadTypeWebRTCBinary)
		stream2 := assoc.getOrCreateStream(2, false, PayloadTypeWebRTCBinary)

		// The first two fragments of a message larger than the buffer fill
		// the window.
		assoc.handleData(receiveWindowTestChunk(100, 1, true, false))
		assoc.handleData(receiveWindowTestChunk(101, 1, false, false))
		require.Zero(t, assoc.getMyReceiverWindowCredit())
		require.False(t, stream1.isReadable())

		// A chunk beyond the next expected TSN is still dropped.
		assoc.handleData(receiveWindowTestChunk(103, 2, true, true))
		require.Equal(t, uint32(101), assoc.peerLastTSN())

		// The next in-sequence chunk completes the message.
		assoc.immediateAckTriggered = false
		assoc.handleData(receiveWindowTestChunk(102, 1, false, true))
		require.Equal(t, uint32(102), assoc.peerLastTSN())
		require.True(t, assoc.immediateAckTriggered, "a probe into a closed window must be acked at once")
		require.True(t, stream1.isReadable())

		// Now the application can free space, so the window applies again.
		assoc.handleData(receiveWindowTestChunk(103, 2, true, true))
		require.Equal(t, uint32(102), assoc.peerLastTSN())
		require.False(t, stream2.isReadable())
	})

	t.Run("drops in-sequence DATA while a message is readable", func(t *testing.T) {
		assoc := newReceiveWindowTestAssoc(t)
		assoc.lock.Lock()
		defer assoc.lock.Unlock()

		stream1 := assoc.getOrCreateStream(1, false, PayloadTypeWebRTCBinary)
		assoc.getOrCreateStream(2, false, PayloadTypeWebRTCBinary)

		assoc.handleData(receiveWindowTestChunk(100, 1, true, true))
		assoc.handleData(receiveWindowTestChunk(101, 2, true, false))
		require.Zero(t, assoc.getMyReceiverWindowCredit())
		require.True(t, stream1.isReadable())

		assoc.handleData(receiveWindowTestChunk(102, 2, false, true))
		require.Equal(t, uint32(101), assoc.peerLastTSN())
	})
}

// TestAssocMessagesExceedingReceiveWindow sends fragmented messages whose
// fragments together exceed the receiver's buffer before any message is
// complete. The receiver must still accept enough of them to complete and
// deliver every message instead of dropping the rest for lack of window.
func TestAssocMessagesExceedingReceiveWindow(t *testing.T) {
	const maxReceiveBufferSize = 16 * 1024

	tests := []struct {
		name         string
		interleaving bool
		streams      int
		messageSize  int
	}{
		{
			// With I-DATA the sender interleaves the fragments of all
			// streams, so every stream holds a partial message when the
			// window fills.
			name:         "interleaved messages on several streams",
			interleaving: true,
			streams:      5,
			messageSize:  8 * 1024,
		},
		{
			name:        "single message larger than the buffer",
			streams:     1,
			messageSize: 3 * maxReceiveBufferSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lim := test.TimeOut(10 * time.Second)
			defer lim.Stop()

			br := test.NewBridge()
			a0, a1, err := createNewAssociationPairWithInterleaving(
				br, ackModeNormal, maxReceiveBufferSize, tt.interleaving, tt.interleaving,
			)
			require.NoError(t, err)
			defer closeAssociationPair(br, a0, a1)
			require.Equal(t, tt.interleaving, a0.useInterleaving)

			senders := make([]*Stream, tt.streams)
			receivers := make([]*Stream, tt.streams)
			for i := range tt.streams {
				senders[i], receivers[i], err = establishSessionPair(br, a0, a1, uint16(i+1)) //nolint:gosec // G115
				require.NoError(t, err)
			}
			payloads := make([][]byte, tt.streams)
			for i, s := range senders {
				payloads[i] = bytes.Repeat([]byte{"abcdefgh"[i]}, tt.messageSize)
				_, err = s.WriteSCTP(payloads[i], PayloadTypeWebRTCBinary)
				require.NoError(t, err)
			}

			readMessagesWhileTicking(t, br, a1, receivers, payloads)
		})
	}
}

// readMessagesWhileTicking reads one message from each receiver, expecting
// the matching payload, while it forwards packets across br.
func readMessagesWhileTicking(t *testing.T, br *test.Bridge, receiver *Association, streams []*Stream, want [][]byte) {
	t.Helper()

	var wg sync.WaitGroup
	errs := make(chan error, len(streams))
	for i, s := range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, len(want[i])+1)
			n, _, err := s.ReadSCTP(buf)
			switch {
			case err != nil:
				errs <- err
			case !bytes.Equal(buf[:n], want[i]):
				errs <- fmt.Errorf("stream %d: got %d bytes, want %d", s.streamIdentifier, n, len(want[i])) //nolint:err113
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(errs)
		close(done)
	}()

	deadline := time.After(5 * time.Second)
	for {
		br.Tick()
		select {
		case <-done:
			for err := range errs {
				require.NoError(t, err)
			}

			return
		case <-deadline:
			receiver.lock.RLock()
			credit := receiver.getMyReceiverWindowCredit()
			receiver.lock.RUnlock()
			require.FailNow(t, "fragmented messages were not delivered", "receive window credit %d", credit)
		case <-time.After(time.Millisecond):
		}
	}
}
