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

func TestAssocTimedLifetimeUsesFirstTransmission(t *testing.T) {
	for _, interleaving := range []bool{false, true} {
		for _, size := range []int{1000, 2000} {
			t.Run(fmt.Sprintf("interleaving=%t/bytes=%d", interleaving, size), func(t *testing.T) {
				br := test.NewBridge()
				a0, a1, err := createNewAssociationPairWithInterleaving(br, ackModeNoDelay, 0, interleaving, interleaving)
				require.NoError(t, err)
				defer closeAssociationPair(br, a0, a1)
				s0, s1, err := establishSessionPair(br, a0, a1, 1)
				require.NoError(t, err)
				a0.rtoMgr.setRTO(50, true)
				const lifetime = 120 * time.Millisecond
				s0.SetReliabilityParams(false, ReliabilityTypeTimed, uint32(lifetime.Milliseconds()))

				var mu sync.Mutex
				var sends []time.Time
				initialCopies := 0
				forwarded := false
				br.Filter(0, func(raw []byte) bool {
					p := &packet{}
					if p.unmarshal(true, raw) != nil {
						return true
					}
					mu.Lock()
					defer mu.Unlock()
					for _, c := range p.chunks {
						switch c := c.(type) {
						case *chunkForwardTSN, *chunkIForwardTSN:
							forwarded = true
						case *chunkPayloadData:
							if len(c.userData) > 0 && c.userData[0] == 0xa1 {
								sends = append(sends, time.Now())
								if c.beginningFragment {
									initialCopies++
								}
								return false
							}
						}
					}
					return true
				})
				_, err = s0.WriteSCTP(bytes.Repeat([]byte{0xa1}, size), PayloadTypeWebRTCBinary)
				require.NoError(t, err)
				require.Eventually(t, func() bool {
					br.Tick()
					mu.Lock()
					defer mu.Unlock()
					return initialCopies >= 2
				}, time.Second, time.Millisecond, "test must exercise a retry before expiry")
				// Keep the policy unchanged. The later message is received and
				// gap-acknowledged, but ordered delivery waits for the lost head.
				// Expiry must release it without depending on another incoming ACK.
				tail := []byte("ordered tail after timed expiry")
				_, err = s0.WriteSCTP(tail, PayloadTypeWebRTCBinary)
				require.NoError(t, err)
				require.Equal(t, [][]byte{tail}, readTimedLifetimeMessages(t, br, s1, 1))
				mu.Lock()
				first, last, sawForward := sends[0], sends[len(sends)-1], forwarded
				mu.Unlock()
				require.True(t, sawForward, "expired ordered message must advance Forward-TSN")
				require.Less(t, last.Sub(first), lifetime+20*time.Millisecond, "retry reset the message lifetime")
				require.Eventually(t, func() bool {
					br.Tick()
					return a0.BufferedAmount() == 0
				}, time.Second, time.Millisecond)
			})
		}
	}
}

func readTimedLifetimeMessages(t *testing.T, br *test.Bridge, stream *Stream, count int) [][]byte {
	t.Helper()
	type result struct {
		data []byte
		err  error
	}
	require.NoError(t, stream.SetReadDeadline(time.Now().Add(2*time.Second)))
	results := make(chan result, count)
	go func() {
		for range count {
			buf := make([]byte, 4096)
			n, _, err := stream.ReadSCTP(buf)
			results <- result{data: buf[:n], err: err}
			if err != nil {
				return
			}
		}
	}()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	var received [][]byte
	for len(received) < count {
		select {
		case value := <-results:
			require.NoError(t, value.err)
			received = append(received, value.data)
		case <-ticker.C:
			br.Tick()
		case <-timer.C:
			require.FailNow(t, "partial-reliability stream did not make progress")
		}
	}
	return received
}
