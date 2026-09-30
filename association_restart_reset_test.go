// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPeerRestartDiscardsPreviousResetGeneration(t *testing.T) {
	assoc := newRackTestAssoc(t)
	t.Cleanup(assoc.closeAllTimers)
	completions := 0
	assoc.OnStreamResetComplete(func(uint16) { completions++ })
	assoc.lock.Lock()
	defer assoc.lock.Unlock()

	assoc.completeStreamResetDirection(7, streamResetOutbound)
	assoc.pendingStreamResets = []uint16{7}
	assoc.peerNextRSN = 400
	assoc.lastReconfigResponse = assoc.createReconfigResponse(399, reconfigResultSuccessPerformed)
	init := &chunkInit{chunkInitCommon: chunkInitCommon{
		initiateTag: 3, initialTSN: 500, numInboundStreams: 10, numOutboundStreams: 11,
	}}
	pkt := &packet{sourcePort: assoc.destinationPort, destinationPort: assoc.sourcePort}
	response, err := assoc.handleInit(pkt, init)
	require.NoError(t, err)
	require.Len(t, response, 1)
	ack, ok := response[0].chunks[0].(*chunkInitAck)
	require.True(t, ok)
	cookie, ok := ack.params[0].(*paramStateCookie)
	require.True(t, ok)
	pkt.verificationTag = ack.initiateTag
	require.Len(t, assoc.handleCookieEcho(pkt, &chunkCookieEcho{cookie: cookie.cookie}), 1)
	require.Empty(t, assoc.pendingStreamResets, "queued resets belong to the previous association")
	require.Equal(t, init.initialTSN, assoc.peerNextRSN)
	require.Nil(t, assoc.lastReconfigResponse)

	assoc.createStream(7, false)
	resetResponse, err := assoc.handleReconfigParam(&paramOutgoingResetRequest{
		reconfigRequestSequenceNumber: init.initialTSN,
		senderLastTSN:                 init.initialTSN - 1,
		streamIdentifiers:             []uint16{7},
	})
	require.NoError(t, err)
	reset, ok := resetResponse.chunks[0].(*chunkReconfig)
	require.True(t, ok)
	result, ok := reset.paramA.(*paramReconfigResponse)
	require.True(t, ok)
	require.Equal(t, reconfigResultSuccessPerformed, result.result)
	require.Zero(t, completions, "an old outbound reset cannot complete a new inbound reset")
	assoc.completeStreamResetDirection(7, streamResetOutbound)
	require.Equal(t, 1, completions)
}
