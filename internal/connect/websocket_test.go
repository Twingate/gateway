// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"io"
	"net"
	"testing"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestUpgradeToWebSocketPassesThroughNativeProtocol(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	greeting := []byte("SSH-2.0-Go\r\n")

	go func() {
		_, _ = client.Write(greeting)
	}()

	conn, err := upgradeToWebSocket(server, zap.NewNop())
	require.NoError(t, err)

	got := make([]byte, len(greeting))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)

	assert.Equal(t, greeting, got, "the peeked bytes must be replayed to the native protocol handler")
}

func TestUpgradeToWebSocketUnwrapsFrames(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close()

	payloads := make(chan []byte, 1)

	go func() {
		accepted, acceptErr := listener.Accept()
		if acceptErr != nil {
			close(payloads)

			return
		}

		defer accepted.Close()

		conn, upgradeErr := upgradeToWebSocket(accepted, zap.NewNop())
		if upgradeErr != nil {
			close(payloads)

			return
		}

		payload := make([]byte, len("SSH-2.0-Browser"))
		if _, readErr := io.ReadFull(conn, payload); readErr != nil {
			close(payloads)

			return
		}

		payloads <- payload
	}()

	//nolint:bodyclose // Dial sets resp.Body to nil once the handshake succeeds
	ws, _, err := websocket.Dial(t.Context(), "ws://"+listener.Addr().String(), nil)
	require.NoError(t, err)

	defer func() { _ = ws.CloseNow() }()

	session := websocket.NetConn(t.Context(), ws, websocket.MessageBinary)

	_, err = session.Write([]byte("SSH-2.0-Browser"))
	require.NoError(t, err)

	payload, ok := <-payloads
	require.True(t, ok, "the WebSocket handshake must complete and yield a byte stream")

	assert.Equal(t, []byte("SSH-2.0-Browser"), payload, "frame payloads must reach the handler as a plain byte stream")
}
