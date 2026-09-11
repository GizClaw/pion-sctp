// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/require"
)

// TestAssocAbandonAfterPeerStreamReset checks that data written on a
// partially reliable stream keeps its policy after the peer resets its
// outgoing stream. The reset unregisters the stream locally while it can
// still send, and a lost chunk must then be abandoned and skipped with
// FORWARD-TSN rather than retransmitted as if it were reliable.
func TestAssocAbandonAfterPeerStreamReset(t *testing.T) {
	for _, interleaving := range []bool{false, true} {
		expectedForwardType := ctForwardTSN
		name := "DATA"
		if interleaving {
			expectedForwardType = ctIForwardTSN
			name = "I-DATA"
		}

		t.Run(name, func(t *testing.T) {
			lim := test.TimeOut(10 * time.Second)
			defer lim.Stop()

			const si uint16 = 1
			br := test.NewBridge()
			a0, a1, err := createNewAssociationPairWithInterleaving(br, ackModeNoDelay, 0, interleaving, interleaving)
			require.NoError(t, err)
			defer closeAssociationPair(br, a0, a1)

			s0, s1, err := establishSessionPair(br, a0, a1, si)
			require.NoError(t, err)
			s0.SetReliabilityParams(false, ReliabilityTypeRexmit, 0)

			// The peer closes its side; a0 unregisters the stream but may
			// keep sending on it.
			require.NoError(t, s1.Close())
			require.Eventually(t, func() bool {
				br.Tick()
				a0.lock.RLock()
				defer a0.lock.RUnlock()
				_, ok := a0.streams[si]

				return !ok
			}, 5*time.Second, 5*time.Millisecond, "peer stream reset was not processed")

			chunkTypes := captureChunkTypes(br, 0)
			br.DropNextNWrites(0, 1)

			sbuf := make([]byte, 1000)
			for i := range uint32(2) {
				binary.BigEndian.PutUint32(sbuf, i)
				_, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
				require.NoError(t, err)
			}

			flushBuffers(br, a0, a1)
			requireEventuallyChunkType(t, chunkTypes, expectedForwardType)

			buf := make([]byte, 2000)
			n, _, err := s1.ReadSCTP(buf)
			require.NoError(t, err)
			require.Equal(t, uint32(1), binary.BigEndian.Uint32(buf[:n]), "the lost message must be abandoned")
		})
	}
}
