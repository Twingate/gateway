// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// testTimeout bounds every blocking wait in these tests.
const testTimeout = 5 * time.Second

// testSSHContext is the connection-level audit context for pairs built by the test fixtures.
var testSSHContext = &sshContext{
	id:            "test-conn",
	username:      "testuser",
	clientVersion: "SSH-2.0-client",
	serverVersion: "SSH-2.0-server",
}

// testSigner generates an ed25519 host/user key for test SSH endpoints.
func testSigner(t *testing.T) ssh.Signer {
	t.Helper()

	keyConf, err := newKeyConfig("ed25519", 0)
	require.NoError(t, err)

	signer, _, err := keyConf.Generate(rand.Reader)
	require.NoError(t, err)

	return signer
}

// netPipe is analogous to net.Pipe, but it uses a real loopback TCP connection, and therefore
// is buffered (net.Pipe deadlocks if both sides start with a write).
func netPipe(t *testing.T) (client, server net.Conn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close()

	client, err = net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	server, err = listener.Accept()
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	return client, server
}

// sshPipe establishes a real SSH connection over netPipe and returns the client and server
// sides. Both sides are torn down on test cleanup when netPipe closes the underlying conns.
func sshPipe(t *testing.T) (client, server *connection) {
	t.Helper()

	return sshPipeWithClose(t, nil, nil)
}

// sshPipeWithClose is sshPipe with an injected transport Close() error on either side (nil
// keeps that side's close real), for driving close-error handling over a real SSH connection.
func sshPipeWithClose(t *testing.T, clientCloseErr, serverCloseErr error) (client, server *connection) {
	t.Helper()

	clientNetConn, serverNetConn := netPipe(t)

	if clientCloseErr != nil {
		clientNetConn = &closeErrConn{Conn: clientNetConn, closeErr: clientCloseErr}
	}

	if serverCloseErr != nil {
		serverNetConn = &closeErrConn{Conn: serverNetConn, closeErr: serverCloseErr}
	}

	hostKey := testSigner(t)
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(hostKey)

	serverReady := make(chan *connection, 1)

	go func() {
		defer close(serverReady)

		conn, channels, requests, err := ssh.NewServerConn(serverNetConn, serverConfig)
		if err != nil {
			return
		}

		serverReady <- &connection{conn: conn, channels: channels, requests: requests}
	}()

	clientConfig := &ssh.ClientConfig{
		User:            "testuser",
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
	}

	conn, channels, requests, err := ssh.NewClientConn(clientNetConn, "", clientConfig)
	require.NoError(t, err)

	client = &connection{conn: conn, channels: channels, requests: requests}

	server, ok := <-serverReady
	require.True(t, ok, "server SSH handshake failed")

	return client, server
}

// closeErrConn wraps a net.Conn so its Close() still closes the conn but returns the injected
// error, keeping the SSH handshake and mux fully real.
type closeErrConn struct {
	net.Conn

	closeErr error
}

func (c *closeErrConn) Close() error {
	_ = c.Conn.Close()

	return c.closeErr
}

// openChannel opens a channel with the given type and extra data from opener to acceptor,
// asserts they arrive intact, and returns both ends.
func openChannel(t *testing.T, opener, acceptor *connection, channelType string, extraData []byte) (openerCh, acceptorCh channel) {
	t.Helper()

	type openResult struct {
		channel channel
		err     error
	}

	opened := make(chan openResult, 1)

	go func() {
		ch, requests, err := opener.conn.OpenChannel(channelType, extraData)
		opened <- openResult{channel: channel{ch: ch, requests: requests}, err: err}
	}()

	select {
	case newChannel, ok := <-acceptor.channels:
		require.True(t, ok, "incoming channels closed")
		require.Equal(t, channelType, newChannel.ChannelType())
		require.Equal(t, string(extraData), string(newChannel.ExtraData()))

		ch, requests, err := newChannel.Accept()
		require.NoError(t, err)

		acceptorCh = channel{ch: ch, requests: requests}
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for channel open")
	}

	select {
	case result := <-opened:
		require.NoError(t, result.err)

		return result.channel, acceptorCh
	case <-time.After(testTimeout):
		t.Fatal("timed out opening channel")

		return channel{}, channel{}
	}
}

// acceptChannel accepts the next incoming channel on conn, discards its requests, and delivers the
// accepted end. It runs off the test goroutine because Accept blocks until the open arrives.
func acceptChannel(t *testing.T, conn *connection) <-chan channel {
	t.Helper()

	accepted := make(chan channel, 1)

	go func() {
		newChannel, ok := <-conn.channels
		if !ok {
			return
		}

		ch, requests, err := newChannel.Accept()
		if err != nil {
			return
		}

		go ssh.DiscardRequests(requests)

		accepted <- channel{ch: ch, requests: requests}
	}()

	return accepted
}

// sendGlobalRequest sends a global request from a background goroutine, since SendRequest with
// WantReply blocks until the far end (the test itself) replies. It returns a function that blocks
// for the (ok, replyPayload, err) result, failing the test if none arrives within testTimeout.
func sendGlobalRequest(conn ssh.Conn, name string, wantReply bool, payload []byte) func(t *testing.T) (ok bool, replyPayload []byte, err error) {
	type result struct {
		ok      bool
		payload []byte
		err     error
	}

	done := make(chan result, 1)

	go func() {
		ok, replyPayload, err := conn.SendRequest(name, wantReply, payload)
		done <- result{ok: ok, payload: replyPayload, err: err}
	}()

	return func(t *testing.T) (bool, []byte, error) {
		t.Helper()

		select {
		case res := <-done:
			return res.ok, res.payload, res.err
		case <-time.After(testTimeout):
			t.Fatal("timed out waiting for global request reply")

			return false, nil, nil
		}
	}
}

// assertSentRequest asserts that a request of wantType arrives on the requests channel within
// testTimeout, and returns it.
func assertSentRequest(t *testing.T, reqs <-chan *ssh.Request, wantType string) *ssh.Request {
	t.Helper()

	select {
	case req, ok := <-reqs:
		require.True(t, ok, "requests channel closed before %q arrived", wantType)
		require.Equal(t, wantType, req.Type)

		return req
	case <-time.After(testTimeout):
		t.Fatalf("timed out waiting for %q request", wantType)

		return nil
	}
}

// readInFull reads exactly n bytes within testTimeout.
func readInFull(t *testing.T, reader io.Reader, n int) []byte {
	t.Helper()

	buf := make([]byte, n)
	done := make(chan error, 1)

	go func() {
		_, err := io.ReadFull(reader, buf)
		done <- err
	}()

	select {
	case err := <-done:
		require.NoError(t, err)

		return buf
	case <-time.After(testTimeout):
		t.Fatal("timed out reading")

		return nil
	}
}

// assertEOF asserts the next read returns io.EOF within testTimeout.
func assertEOF(t *testing.T, reader io.Reader) {
	t.Helper()

	done := make(chan error, 1)

	go func() {
		_, err := reader.Read(make([]byte, 1))
		done <- err
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, io.EOF)
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for EOF")
	}
}

// assertConnClosed fails the test unless the connection's Wait() returns within testTimeout.
func assertConnClosed(t *testing.T, conn ssh.Conn) {
	t.Helper()

	done := make(chan struct{})

	go func() {
		_ = conn.Wait()

		close(done)
	}()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("connection was not closed")
	}
}

// waitDone fails the test if done is not closed within testTimeout.
func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for done channel to close")
	}
}
