// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPeerRestartDiscardsPreviousResetGeneration(t *testing.T) {
	a := newRackTestAssoc(t)
	t.Cleanup(a.closeAllTimers)
	completions := 0
	a.OnStreamResetComplete(func(uint16) { completions++ })
	a.lock.Lock()
	defer a.lock.Unlock()

	a.completeStreamResetDirection(7, streamResetOutbound)
	a.pendingStreamResets = []uint16{7}
	a.peerNextRSN = 400
	a.lastReconfigResponse = a.createReconfigResponse(399, reconfigResultSuccessPerformed)
	init := &chunkInit{chunkInitCommon: chunkInitCommon{
		initiateTag: 3, initialTSN: 500, numInboundStreams: 10, numOutboundStreams: 11,
	}}
	pkt := &packet{sourcePort: a.destinationPort, destinationPort: a.sourcePort}
	response, err := a.handleInit(pkt, init)
	require.NoError(t, err)
	require.Len(t, response, 1)
	ack, ok := response[0].chunks[0].(*chunkInitAck)
	require.True(t, ok)
	cookie, ok := ack.params[0].(*paramStateCookie)
	require.True(t, ok)
	pkt.verificationTag = ack.initiateTag
	require.Len(t, a.handleCookieEcho(pkt, &chunkCookieEcho{cookie: cookie.cookie}), 1)
	require.Empty(t, a.pendingStreamResets, "queued resets belong to the previous association")
	require.Equal(t, init.initialTSN, a.peerNextRSN)
	require.Nil(t, a.lastReconfigResponse)

	a.createStream(7, false)
	resetResponse, err := a.handleReconfigParam(&paramOutgoingResetRequest{
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
	a.completeStreamResetDirection(7, streamResetOutbound)
	require.Equal(t, 1, completions)
}
