// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSSHProxy_Start drives a real SSH client through the accept loop to an in-memory upstream,
// verifying the full wiring (session output round-trips), that the served connection is removed
// from the map once it completes, and that closing the listener makes Start return cleanly.
func TestSSHProxy_Start(t *testing.T) {
	sshProxy := newTestProxy(t)
	upstream := newEchoServer(t, gatewayUserCAPublicKey(t, sshProxy))
	listener := newTestListener(t, upstream.addr)

	startDone := make(chan error, 1)

	go func() {
		startDone <- sshProxy.Start(t.Context(), listener)
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	client, err := dialDownstream(t, clientConn, upstream.addr)
	require.NoError(t, err)

	session, err := client.NewSession()
	require.NoError(t, err)

	output, err := session.Output("hello from gateway")
	require.NoError(t, err)
	assert.Equal(t, "hello from gateway", string(output))

	_ = client.Close()

	// The served connection is removed from the map once serving completes.
	require.Eventually(t, func() bool {
		sshProxy.mu.Lock()
		defer sshProxy.mu.Unlock()

		return len(sshProxy.connsMap) == 0
	}, 2*time.Second, 10*time.Millisecond, "served connection should be removed from the map")

	// Closing the listener makes Accept return net.ErrClosed, so Start returns cleanly.
	require.NoError(t, listener.Close())

	select {
	case err := <-startDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after listener close")
	}
}

// TestSSHProxy_serveConn_RejectsWhenShuttingDown verifies that a connection handed to serveConn
// after shutdown has begun is closed and rejected with errShuttingDown rather than served.
func TestSSHProxy_serveConn_RejectsWhenShuttingDown(t *testing.T) {
	sshProxy := newTestProxy(t)
	sshProxy.Shutdown(t.Context())

	clientDownstreamConn, serverDownstreamConn := newDownstreamConn(t, "unused:22")

	err := sshProxy.serveConn(t.Context(), serverDownstreamConn)
	require.ErrorIs(t, err, errShuttingDown)

	// The rejected connection is closed, so the client end sees EOF rather than a handshake.
	require.NoError(t, clientDownstreamConn.SetReadDeadline(time.Now().Add(time.Second)))

	_, readErr := clientDownstreamConn.Read(make([]byte, 1))
	require.Error(t, readErr)
}

// TestSSHProxy_serveConn_DownstreamHandshakeFailure verifies serveConn surfaces a failed
// downstream handshake and bails before dialing the upstream.
func TestSSHProxy_serveConn_DownstreamHandshakeFailure(t *testing.T) {
	sshProxy := newTestProxy(t)

	clientDownstreamConn, serverDownstreamConn := newDownstreamConn(t, "unused:22")

	// Closing the client end before any SSH exchange makes the server handshake fail.
	_ = clientDownstreamConn.Close()

	// serveConn must surface the handshake error instead of proceeding to the upstream (proceeding
	// would dereference the nil downstream conn).
	err := sshProxy.serveConn(t.Context(), serverDownstreamConn)
	require.ErrorContains(t, err, "downstream SSH handshake failed")
}

// TestSSHProxy_serveConn_UpstreamConnectionFailure verifies that, after a successful downstream
// handshake, a failure to reach the upstream is surfaced.
func TestSSHProxy_serveConn_UpstreamConnectionFailure(t *testing.T) {
	sshProxy := newTestProxy(t)

	// Reserve a loopback address then close it so dialing is refused immediately.
	refused, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	refusedAddr := refused.Addr().String()
	require.NoError(t, refused.Close())

	clientDownstreamConn, serverDownstreamConn := newDownstreamConn(t, refusedAddr)

	serveErr := make(chan error, 1)

	go func() {
		serveErr <- sshProxy.serveConn(t.Context(), serverDownstreamConn)
	}()

	// The downstream handshake succeeds; the proxy fails only once it dials the upstream.
	client, err := dialDownstream(t, clientDownstreamConn, refusedAddr)
	require.NoError(t, err)

	defer func() { _ = client.Close() }()

	select {
	case err := <-serveErr:
		require.ErrorContains(t, err, "failed to dial upstream")
	case <-time.After(2 * time.Second):
		t.Fatal("serveConn did not return")
	}

	assert.Empty(t, sshProxy.connsMap)
}

// TestSSHProxy_serveConn_UpstreamSSHHandshakeFailure verifies that an upstream that accepts TCP
// but does not complete the SSH handshake is surfaced as an error.
func TestSSHProxy_serveConn_UpstreamSSHHandshakeFailure(t *testing.T) {
	sshProxy := newTestProxy(t)

	// Upstream accepts the TCP connection then closes it without an SSH handshake.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { _ = upstream.Close() })

	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}

			_ = conn.Close()
		}
	}()

	clientDownstreamConn, serverDownstreamConn := newDownstreamConn(t, upstream.Addr().String())

	serveErr := make(chan error, 1)

	go func() {
		serveErr <- sshProxy.serveConn(t.Context(), serverDownstreamConn)
	}()

	client, err := dialDownstream(t, clientDownstreamConn, upstream.Addr().String())
	require.NoError(t, err)

	defer func() { _ = client.Close() }()

	select {
	case err := <-serveErr:
		require.ErrorContains(t, err, "upstream SSH handshake failed")
	case <-time.After(2 * time.Second):
		t.Fatal("serveConn did not return")
	}

	assert.Empty(t, sshProxy.connsMap)
}

// TestSSHProxy_Shutdown_WithActiveConnection verifies Shutdown tears down a live connection.
func TestSSHProxy_Shutdown_WithActiveConnection(t *testing.T) {
	sshProxy := newTestProxy(t)
	upstream := newEchoServer(t, gatewayUserCAPublicKey(t, sshProxy))

	clientDownstreamConn, serverDownstreamConn := newDownstreamConn(t, upstream.addr)

	serveDone := make(chan error, 1)

	go func() {
		serveDone <- sshProxy.Serve(t.Context(), serverDownstreamConn)
	}()

	client, err := dialDownstream(t, clientDownstreamConn, upstream.addr)
	require.NoError(t, err)

	// The connection pair is tracked once both handshakes complete, before any channel opens.
	require.Eventually(t, func() bool {
		sshProxy.mu.Lock()
		defer sshProxy.mu.Unlock()

		return len(sshProxy.connsMap) == 1
	}, time.Second, 10*time.Millisecond, "connection should be tracked")

	sshProxy.Shutdown(t.Context())

	assert.True(t, sshProxy.shuttingDown, "proxy should be in shutting down state")

	select {
	case err := <-serveDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Serve should have completed after shutdown")
	}

	sshProxy.mu.Lock()
	assert.Empty(t, sshProxy.connsMap, "all connections should be removed after shutdown")
	sshProxy.mu.Unlock()

	_ = client.Close()
}
