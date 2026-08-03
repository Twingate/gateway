// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"go.uber.org/zap"
)

var errWebSocketHandshake = errors.New("WebSocket handshake did not complete")

// httpRequestPrefix is the shortest prefix that separates a WebSocket handshake from the native
// protocol of every resource type GATClaims.MayUseWebSocket allows through this path.
var httpRequestPrefix = []byte("GET ")

const webSocketHandshakeTimeout = 10 * time.Second

// upgradeToWebSocket returns the byte stream carrying the tunnel payload. A browser cannot open a
// raw TCP tunnel, so it reaches the resource over a WebSocket instead; that payload is unwrapped
// from its frames, while a native client's stream is returned untouched.
func upgradeToWebSocket(conn net.Conn, logger *zap.Logger) (net.Conn, error) {
	buffered := &bufferedConn{Conn: conn, reader: bufio.NewReader(conn)}

	if err := conn.SetReadDeadline(time.Now().Add(webSocketHandshakeTimeout)); err != nil {
		return nil, err
	}

	prefix, err := buffered.reader.Peek(len(httpRequestPrefix))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(prefix, httpRequestPrefix) {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return nil, err
		}

		return buffered, nil
	}

	sessions := make(chan net.Conn, 1)

	server := &http.Server{
		ReadHeaderTimeout: webSocketHandshakeTimeout,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
				// The page is served by the Twingate Client, not by the resource's own origin.
				InsecureSkipVerify: true,
			})
			if err != nil {
				logger.Error("failed to accept WebSocket", zap.Error(err))
				close(sessions)

				return
			}

			// Accept hijacks the connection, so the deadline the server set for reading the
			// handshake would otherwise expire mid-session.
			if err := conn.SetDeadline(time.Time{}); err != nil {
				logger.Error("failed to clear handshake deadline", zap.Error(err))
				close(sessions)

				return
			}

			// The request context is canceled as soon as the handler returns, which would tear
			// down a session that has only just started.
			sessions <- websocket.NetConn(context.WithoutCancel(r.Context()), ws, websocket.MessageBinary)
		}),
	}

	go func() {
		_ = server.Serve(&singleConnListener{conn: buffered})
	}()

	select {
	case session, ok := <-sessions:
		if !ok {
			return nil, errWebSocketHandshake
		}

		return session, nil
	case <-time.After(webSocketHandshakeTimeout):
		return nil, errWebSocketHandshake
	}
}

// bufferedConn replays bytes already read from the underlying connection, so the head of the
// stream can be inspected before deciding who consumes it.
type bufferedConn struct {
	net.Conn

	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// singleConnListener serves one already-accepted connection to an http.Server, which owns the
// WebSocket handshake so that it does not have to be written by hand.
type singleConnListener struct {
	conn net.Conn
	once sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var conn net.Conn

	l.once.Do(func() { conn = l.conn })

	if conn == nil {
		return nil, net.ErrClosed
	}

	return conn, nil
}

// Close is a no-op because the connection outlives the server that performed its handshake.
func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
