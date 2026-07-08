// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
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

// testSigner generates an ed25519 host/user key for test SSH endpoints.
func testSigner(t *testing.T) ssh.Signer {
	t.Helper()

	keyConf, err := newKeyConfig("ed25519", 0)
	require.NoError(t, err)

	signer, _, err := keyConf.Generate(rand.Reader)
	require.NoError(t, err)

	return signer
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

// proxyConns is the connection-layer fixture: an SSHConnPair serving between two real SSH
// connections, with the proxy holding the same ends it does in production (the SSH server end
// toward the downstream client, the SSH client end toward the upstream server):
//
//	         downstream conn   +----------------------------------+  upstream conn
//	client <-----------------> | proxyDownstream    proxyUpstream | <-----------------> server
//	                           +-------------- proxy -------------+
//
// The tests drive the far ends (client and server) and assert only there.
type proxyConns struct {
	pair *SSHConnPair

	client *connection
	server *connection

	// done closes when the pair's serve() returns.
	done <-chan struct{}
}

// newServingConnPair builds a proxyConns fixture and serves its SSHConnPair in the background.
func newServingConnPair(t *testing.T) *proxyConns {
	t.Helper()

	client, proxyDownstream := sshPipe(t)
	proxyUpstream, server := sshPipe(t)

	pair := NewSSHConnPair(zaptest.NewLogger(t), testSSHContext, *proxyDownstream, *proxyUpstream)

	done := make(chan struct{})

	go func() {
		pair.serve()
		close(done)
	}()

	return &proxyConns{pair: pair, client: client, server: server, done: done}
}

// close closes both far ends and waits for serve() to return.
func (p *proxyConns) close(t *testing.T) {
	t.Helper()

	_ = p.client.conn.Close()
	_ = p.server.conn.Close()

	waitServeDone(t, p.done)
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

// newDeadChannel opens a channel of the given type from a real SSH client, captures the
// matching ssh.NewChannel at the server end without answering it, and closes the server
// connection, so any later mux send on the returned channel (Accept or Reject) fails.
func newDeadChannel(t *testing.T, channelType string) ssh.NewChannel {
	t.Helper()

	client, server := sshPipe(t)

	// OpenChannel blocks until the channel is answered or the connection dies, so it must run
	// off the test goroutine; the failed result is discarded.
	go func() {
		_, _, _ = client.conn.OpenChannel(channelType, nil)
	}()

	select {
	case newChannel := <-server.channels:
		require.NoError(t, server.conn.Close())

		return newChannel
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for the channel open")

		return nil
	}
}

// forwardDeadChannel drives forwardChannels (downstream direction) with a single dead source
// channel of the given type over targetConn, returning once the one-shot stream drains.
func forwardDeadChannel(t *testing.T, pair *SSHConnPair, targetConn ssh.Conn, channelType string) {
	t.Helper()

	channels := make(chan ssh.NewChannel, 1)
	channels <- newDeadChannel(t, channelType)

	close(channels)

	pair.forwardChannels(channels, targetConn, disallowedDownstreamChannelTypes, labelDownstream, labelUpstream)
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
		require.True(t, ok, "channel stream closed")
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

// sendGlobalRequest sends a global request from a background goroutine and returns a function
// that blocks for its (ok, replyPayload, err) result. SendRequest with WantReply blocks until
// the reply arrives, which the test itself must produce at the far end, so the send cannot run
// on the test goroutine. The returned function fails the test if no reply arrives within
// testTimeout.
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

// recvForwardedReq receives the next request on the given stream and asserts its type.
func recvForwardedReq(t *testing.T, reqs <-chan *ssh.Request, wantType string) *ssh.Request {
	t.Helper()

	select {
	case req, ok := <-reqs:
		require.True(t, ok, "request stream closed before %q arrived", wantType)
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

// waitServeDone fails the test if serve() does not return within testTimeout.
func waitServeDone(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for serve() to return")
	}
}

func TestConnPair_ForwardsChannels(t *testing.T) {
	// The table proves per-direction open/accept forwarding preserves the channel type and extra
	// data and spawns exactly one channel pair.
	tests := []struct {
		name         string
		channelType  string
		fromUpstream bool
	}{
		{name: "downstream to upstream", channelType: "direct-tcpip"},
		{name: "upstream to downstream", channelType: "forwarded-tcpip", fromUpstream: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conns := newServingConnPair(t)

			opener, acceptor := conns.client, conns.server
			if tt.fromUpstream {
				opener, acceptor = conns.server, conns.client
			}

			// openChannel asserts the forwarded open preserves the type and extra data.
			openChannel(t, opener, acceptor, tt.channelType, []byte("original-extra-data"))

			// The count is only settled once serve() has returned.
			conns.close(t)
			assert.Equal(t, 1, conns.pair.ChannelsOpened())
		})
	}
}

func TestConnPair_ConcurrentChannels(t *testing.T) {
	// An open channel must not block new ones: each pair is served on its own goroutine.
	conns := newServingConnPair(t)

	firstOpener, firstAcceptor := openChannel(t, conns.client, conns.server, "direct-tcpip", nil)
	secondOpener, secondAcceptor := openChannel(t, conns.client, conns.server, "direct-tcpip", nil)

	_, err := secondOpener.ch.Write([]byte("second"))
	require.NoError(t, err)
	assert.Equal(t, "second", string(readInFull(t, secondAcceptor.ch, len("second"))))

	// The first channel still works after the second one opened and exchanged data.
	_, err = firstOpener.ch.Write([]byte("first"))
	require.NoError(t, err)
	assert.Equal(t, "first", string(readInFull(t, firstAcceptor.ch, len("first"))))

	conns.close(t)
	assert.Equal(t, 2, conns.pair.ChannelsOpened())
}

func TestConnPair_ChannelPolicy(t *testing.T) {
	// Every denylisted type per direction must be rejected with Prohibited.
	tests := []struct {
		name            string
		fromUpstream    bool
		disallowedTypes []string
	}{
		{name: "from downstream", disallowedTypes: []string{"x11", "forwarded-tcpip"}},
		{name: "from upstream", fromUpstream: true, disallowedTypes: []string{"session", "direct-tcpip", "x11"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conns := newServingConnPair(t)

			opener := conns.client
			if tt.fromUpstream {
				opener = conns.server
			}

			for _, channelType := range tt.disallowedTypes {
				_, _, err := opener.conn.OpenChannel(channelType, nil)

				var openErr *ssh.OpenChannelError

				require.ErrorAs(t, err, &openErr)
				assert.Equal(t, ssh.Prohibited, openErr.Reason, "channel type %q must be rejected", channelType)
			}

			conns.close(t)
		})
	}
}

func TestConnPair_TargetOpenChannelFailure(t *testing.T) {
	conns := newServingConnPair(t)

	// The upstream server refuses every open with its own reason; the proxy must reject the
	// source with ConnectionFailed, not echo the upstream's reason.
	go func() {
		for newChannel := range conns.server.channels {
			_ = newChannel.Reject(ssh.Prohibited, "upstream refuses")
		}
	}()

	_, _, err := conns.client.conn.OpenChannel("direct-tcpip", nil)

	var openErr *ssh.OpenChannelError

	require.ErrorAs(t, err, &openErr)
	assert.Equal(t, ssh.ConnectionFailed, openErr.Reason)

	conns.close(t)
	assert.Zero(t, conns.pair.ChannelsOpened())
}

func TestConnPair_SourceAcceptFailure(t *testing.T) {
	// A source Accept() fails only on a dead transport, which a serving pair cannot produce, so
	// this drives forwardChannels directly with a dead source channel over a live upstream that
	// accepts the forwarded target open.
	proxyUpstream, upstreamServer := sshPipe(t)
	target := acceptChannel(t, upstreamServer)

	core, logs := observer.New(zap.DebugLevel)
	pair := NewSSHConnPair(zap.New(core), testSSHContext, connection{}, *proxyUpstream)
	forwardDeadChannel(t, pair, proxyUpstream.conn, "direct-tcpip")

	// The already-opened target channel is closed again.
	select {
	case targetCh := <-target:
		assertEOF(t, targetCh.ch)
	case <-time.After(testTimeout):
		t.Fatal("target channel was never opened")
	}

	assert.NotEmpty(t, logs.FilterMessage("Failed to accept source channel").All())
	assert.Zero(t, pair.ChannelsOpened(), "a failed accept must not count as an opened channel")
}

func TestConnPair_ForwardsGlobalRequests(t *testing.T) {
	tests := []struct {
		name         string
		fromUpstream bool
		reqType      string
		payload      []byte
		wantReply    bool
		replyOK      bool
		replyPayload []byte
	}{
		{
			// tcpip-forward is client→server, so only the downstream end sends it; its success
			// reply carries a payload (the bound port), which must round-trip.
			name:         "downstream to upstream",
			reqType:      "tcpip-forward",
			payload:      []byte("forward-payload"),
			wantReply:    true,
			replyOK:      true,
			replyPayload: ssh.Marshal(struct{ Port uint32 }{Port: 8022}),
		},
		{
			name:         "upstream to downstream",
			fromUpstream: true,
			reqType:      "keepalive@openssh.com",
			payload:      []byte("ping"),
			wantReply:    true,
			replyOK:      true,
		},
		{
			name:         "failure reply propagated",
			fromUpstream: true,
			reqType:      "keepalive@openssh.com",
			payload:      []byte("ping"),
			wantReply:    true,
			replyOK:      false,
		},
		{
			name:    "forward wantReply=false and return immediately",
			reqType: "no-more-sessions@openssh.com",
			payload: []byte("no-reply"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conns := newServingConnPair(t)

			sender, receiver := conns.client, conns.server
			if tt.fromUpstream {
				sender, receiver = conns.server, conns.client
			}

			awaitReply := sendGlobalRequest(sender.conn, tt.reqType, tt.wantReply, tt.payload)

			forwarded := recvForwardedReq(t, receiver.requests, tt.reqType)
			assert.Equal(t, tt.wantReply, forwarded.WantReply)
			assert.Equal(t, tt.payload, forwarded.Payload)

			if tt.wantReply {
				require.NoError(t, forwarded.Reply(tt.replyOK, tt.replyPayload))
			}

			// A wantReply=false request expects no reply, so SendRequest returns (false, nil).
			ok, replyPayload, err := awaitReply(t)
			require.NoError(t, err)
			assert.Equal(t, tt.replyOK, ok)
			assert.Equal(t, string(tt.replyPayload), string(replyPayload))

			conns.close(t)
		})
	}
}

func TestConnPair_GlobalRequestPolicy(t *testing.T) {
	// Every denylisted type per direction must be replied false without reaching the far end (a
	// forwarded request would block for a reply nobody sends and time out instead). Sending the
	// types in turn also proves the loop keeps serving after a denial.
	tests := []struct {
		name            string
		fromUpstream    bool
		disallowedTypes []string
	}{
		{name: "from upstream", fromUpstream: true, disallowedTypes: []string{"tcpip-forward", "cancel-tcpip-forward"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conns := newServingConnPair(t)

			sender := conns.client
			if tt.fromUpstream {
				sender = conns.server
			}

			for _, reqType := range tt.disallowedTypes {
				ok, _, err := sendGlobalRequest(sender.conn, reqType, true, nil)(t)
				require.NoError(t, err)
				assert.False(t, ok, "global request type %q must be rejected", reqType)
			}

			conns.close(t)
		})
	}
}

func TestConnPair_GlobalRequestSendError(t *testing.T) {
	// SendRequest fails only on a dead transport, and killing the upstream mid-serve races the
	// cross-close teardown of the downstream side, so this drives forwardGlobalRequests
	// directly: a real pending request from a live source connection, forwarded to a real but
	// already-closed target connection.
	downstreamClient, proxyDownstream := sshPipe(t)
	awaitReply := sendGlobalRequest(downstreamClient.conn, "tcpip-forward", true, []byte("payload"))
	req := recvForwardedReq(t, proxyDownstream.requests, "tcpip-forward")

	proxyUpstream, _ := sshPipe(t)
	require.NoError(t, proxyUpstream.conn.Close())

	requests := make(chan *ssh.Request, 1)
	requests <- req

	close(requests)

	core, logs := observer.New(zap.DebugLevel)
	pair := NewSSHConnPair(zap.New(core), testSSHContext, *proxyDownstream, *proxyUpstream)
	pair.forwardGlobalRequests(requests, proxyUpstream.conn, nil, labelDownstream, labelUpstream)

	// The failed forward is logged and the origin gets a failure reply.
	ok, _, err := awaitReply(t)
	require.NoError(t, err)
	assert.False(t, ok, "the origin must get a failure reply when the forward fails")
	assert.NotEmpty(t, logs.FilterMessage("Failed to forward global request").All())
}

func TestConnPair_CrossClose(t *testing.T) {
	// Closing either side must tear down the other and let serve() return, releasing its six
	// watcher/forwarder goroutines.
	tests := []struct {
		name          string
		closeUpstream bool
	}{
		{name: "downstream close tears down upstream"},
		{name: "upstream close tears down downstream", closeUpstream: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conns := newServingConnPair(t)

			closing, other := conns.client, conns.server
			if tt.closeUpstream {
				closing, other = conns.server, conns.client
			}

			require.NoError(t, closing.conn.Close())

			assertConnClosed(t, other.conn)
			waitServeDone(t, conns.done)
		})
	}
}

func TestConnPair_CloseErrors(t *testing.T) {
	tests := []struct {
		name string
		// wantMsg is the log the run must produce; empty asserts nothing is logged.
		wantMsg string
		run     func(t *testing.T, logger *zap.Logger)
	}{
		{
			name:    "close logs downstream close error",
			wantMsg: "Failed to close downstream connection",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				_, proxyDownstream := sshPipeWithClose(t, nil, errors.New("close failed"))
				proxyUpstream, _ := sshPipe(t)

				NewSSHConnPair(logger, testSSHContext, *proxyDownstream, *proxyUpstream).close()
			},
		},
		{
			name:    "close logs upstream close error",
			wantMsg: "Failed to close upstream connection",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				_, proxyDownstream := sshPipe(t)
				proxyUpstream, _ := sshPipeWithClose(t, errors.New("close failed"), nil)

				NewSSHConnPair(logger, testSSHContext, *proxyDownstream, *proxyUpstream).close()
			},
		},
		{
			name: "close ignores ErrClosed on already-closed connections",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				_, proxyDownstream := sshPipe(t)
				proxyUpstream, _ := sshPipe(t)

				require.NoError(t, proxyDownstream.conn.Close())
				require.NoError(t, proxyUpstream.conn.Close())

				NewSSHConnPair(logger, testSSHContext, *proxyDownstream, *proxyUpstream).close()
			},
		},
		{
			name:    "cross-close logs close error",
			wantMsg: "Failed to close upstream connection",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				downstreamClient, proxyDownstream := sshPipe(t)
				proxyUpstream, _ := sshPipeWithClose(t, errors.New("close failed"), nil)

				pair := NewSSHConnPair(logger, testSSHContext, *proxyDownstream, *proxyUpstream)
				done := make(chan struct{})

				go func() {
					pair.serve()
					close(done)
				}()

				// Closing the downstream far end makes serve() cross-close the upstream
				// connection, whose Close() fails.
				require.NoError(t, downstreamClient.conn.Close())
				waitServeDone(t, done)
			},
		},
		{
			name:    "cross-close logs downstream close error",
			wantMsg: "Failed to close downstream connection",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				_, proxyDownstream := sshPipeWithClose(t, nil, errors.New("close failed"))
				proxyUpstream, upstreamServer := sshPipe(t)

				pair := NewSSHConnPair(logger, testSSHContext, *proxyDownstream, *proxyUpstream)
				done := make(chan struct{})

				go func() {
					pair.serve()
					close(done)
				}()

				// Closing the upstream far end makes serve() cross-close the downstream
				// connection, whose Close() fails.
				require.NoError(t, upstreamServer.conn.Close())
				waitServeDone(t, done)
			},
		},
		{
			name:    "reject of a disallowed channel on a dead source",
			wantMsg: "Failed to reject channel",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				proxyUpstream, _ := sshPipe(t)
				require.NoError(t, proxyUpstream.conn.Close())

				pair := NewSSHConnPair(logger, testSSHContext, connection{}, *proxyUpstream)
				forwardDeadChannel(t, pair, proxyUpstream.conn, "x11")
			},
		},
		{
			name:    "reject after target open failure on a dead source",
			wantMsg: "Failed to reject source channel",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				// The closed target connection fails the open, then the reject of the dead
				// source channel fails too.
				proxyUpstream, _ := sshPipe(t)
				require.NoError(t, proxyUpstream.conn.Close())

				pair := NewSSHConnPair(logger, testSSHContext, connection{}, *proxyUpstream)
				forwardDeadChannel(t, pair, proxyUpstream.conn, "direct-tcpip")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)

			tt.run(t, zap.New(core))

			if tt.wantMsg == "" {
				assert.Empty(t, logs.All(), "an expected close error must not be logged")
			} else {
				assert.NotEmpty(t, logs.FilterMessage(tt.wantMsg).All())
			}
		})
	}
}
