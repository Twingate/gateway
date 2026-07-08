// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/crypto/ssh"
)

// testTimeout bounds every blocking wait in these tests.
const testTimeout = 5 * time.Second

// proxyChannels is the channel-layer fixture: one channel proxied between two real SSH
// connections, exposing all four ends:
//
//	        downstream channel  +----------------------------------+  upstream channel
//	client <------------------> | proxyDownstream    proxyUpstream | <------------------> server
//	                            +-------------- proxy -------------+
//
// The proxy-held ends feed SSHChannelPair (source = proxyDownstream, target = proxyUpstream).
type proxyChannels struct {
	channelType string

	// Optional per-test timeout overrides applied in serve(); zero leaves the pair's default.
	sessionStartTimeout time.Duration
	channelCloseTimeout time.Duration

	client          channel
	proxyDownstream channel
	proxyUpstream   channel
	server          channel
}

// newProxyChannels proxies one channel of the given type across two real SSH connections:
// the client opens toward the proxy, and the proxy opens toward the server, mirroring
// forwardChannels. Global requests on all connection ends are discarded.
func newProxyChannels(t *testing.T, channelType string) *proxyChannels {
	t.Helper()

	clientConn, proxyDownstreamConn := sshPipe(t)
	proxyUpstreamConn, serverConn := sshPipe(t)

	for _, end := range []*connection{clientConn, proxyDownstreamConn, proxyUpstreamConn, serverConn} {
		go ssh.DiscardRequests(end.requests)
	}

	channels := &proxyChannels{channelType: channelType}
	channels.client, channels.proxyDownstream = openChannel(t, clientConn, proxyDownstreamConn, channelType)
	channels.proxyUpstream, channels.server = openChannel(t, proxyUpstreamConn, serverConn, channelType)

	return channels
}

// serve builds an SSHChannelPair over the proxy-held ends and runs its serve() in the
// background; the returned channel closes when serve returns.
func (p *proxyChannels) serve(t *testing.T) <-chan struct{} {
	t.Helper()

	sshCtx := &sshContext{
		id:            "test-conn",
		username:      "testuser",
		clientVersion: "SSH-2.0-client",
		serverVersion: "SSH-2.0-server",
	}

	pair := NewSSHChannelPair(
		zaptest.NewLogger(t),
		newSSHChannelContext(sshCtx, p.channelType, labelDownstream, labelUpstream),
		"testuser",
		p.proxyDownstream,
		p.proxyUpstream,
	)

	if p.sessionStartTimeout != 0 {
		pair.sessionStartTimeout = p.sessionStartTimeout
	}

	if p.channelCloseTimeout != 0 {
		pair.channelCloseTimeout = p.channelCloseTimeout
	}

	done := make(chan struct{})

	go func() {
		pair.serve()
		close(done)
	}()

	return done
}

// close closes the client and server ends and waits for serve() to finish.
func (p *proxyChannels) close(t *testing.T, done <-chan struct{}) {
	t.Helper()

	_ = p.client.ch.Close()
	_ = p.server.ch.Close()

	waitServeDone(t, done)
}

// openChannel opens a channel from opener to acceptor and returns both ends.
func openChannel(t *testing.T, opener, acceptor *connection, channelType string) (openerEnd, acceptorEnd channel) {
	t.Helper()

	type openResult struct {
		channel channel
		err     error
	}

	opened := make(chan openResult, 1)

	go func() {
		ch, requests, err := opener.conn.OpenChannel(channelType, nil)
		opened <- openResult{channel: channel{ch: ch, requests: requests}, err: err}
	}()

	select {
	case newChannel, ok := <-acceptor.channels:
		require.True(t, ok, "channel stream closed")

		ch, requests, err := newChannel.Accept()
		require.NoError(t, err)

		acceptorEnd = channel{ch: ch, requests: requests}
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for channel open")
	}

	select {
	case result := <-opened:
		require.NoError(t, result.err)

		return result.channel, acceptorEnd
	case <-time.After(testTimeout):
		t.Fatal("timed out opening channel")

		return channel{}, channel{}
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

// sendRequest sends a channel request from a background goroutine and returns a function
// that blocks for its (ok, err) result. SendRequest with WantReply blocks until the reply
// arrives, which the test itself must produce at the far end, so the send cannot run on the
// test goroutine. The returned function fails the test if no reply arrives within testTimeout.
func sendRequest(ch ssh.Channel, name string, wantReply bool, payload []byte) func(t *testing.T) (ok bool, err error) {
	type result struct {
		ok  bool
		err error
	}

	done := make(chan result, 1)

	go func() {
		ok, err := ch.SendRequest(name, wantReply, payload)
		done <- result{ok: ok, err: err}
	}()

	return func(t *testing.T) (bool, error) {
		t.Helper()

		select {
		case res := <-done:
			return res.ok, res.err
		case <-time.After(testTimeout):
			t.Fatal("timed out waiting for request reply")

			return false, nil
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

// waitReqChanClosed asserts the request stream closes within testTimeout without delivering
// another request.
func waitReqChanClosed(t *testing.T, reqs <-chan *ssh.Request) {
	t.Helper()

	select {
	case req, ok := <-reqs:
		require.False(t, ok, "expected request stream to close, got request %v", req)
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for request stream to close")
	}
}

func TestChannelPair_ForwardsData(t *testing.T) {
	channels := newProxyChannels(t, "direct-tcpip")
	done := channels.serve(t)

	// No session gate for non-"session" channel types: both directions flow immediately,
	// written concurrently before either side reads.
	_, err := channels.client.ch.Write([]byte("from downstream"))
	require.NoError(t, err)

	_, err = channels.server.ch.Write([]byte("from upstream"))
	require.NoError(t, err)

	assert.Equal(t, "from downstream", string(readInFull(t, channels.server.ch, len("from downstream"))))
	assert.Equal(t, "from upstream", string(readInFull(t, channels.client.ch, len("from upstream"))))

	channels.close(t, done)
}

func TestChannelPair_ForwardsRequests(t *testing.T) {
	tests := []struct {
		name       string
		fromTarget bool
		reqType    string
		payload    []byte
		wantReply  bool
		replyOK    bool
	}{
		{
			name:      "forward source to target",
			reqType:   "test-req@twingate.com",
			payload:   []byte("payload-source"),
			wantReply: true,
			replyOK:   true,
		},
		{
			name:       "forward target to source",
			fromTarget: true,
			reqType:    "test-req@twingate.com",
			payload:    []byte("payload-target"),
			wantReply:  true,
			replyOK:    true,
		},
		{
			name:      "failure reply propagated to origin",
			reqType:   "test-req@twingate.com",
			payload:   []byte("denied"),
			wantReply: true,
			replyOK:   false,
		},
		{
			name:    "forward wantReply=false and return immediately",
			reqType: "test-req@twingate.com",
			payload: []byte("no-reply"),
		},
		{
			// A malformed payload for a parsed type is still forwarded verbatim: the handler
			// logs the parse error but does not drop the request. exec is parsed yet has no
			// callback, so this row is direction-agnostic.
			name:      "malformed payload forwarded verbatim",
			reqType:   "exec",
			payload:   []byte("not-a-valid-exec-payload"),
			wantReply: true,
			replyOK:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			channels := newProxyChannels(t, "direct-tcpip")
			done := channels.serve(t)

			// The client drives the source end, the server the target end.
			from, to := channels.client, channels.server
			if tt.fromTarget {
				from, to = channels.server, channels.client
			}

			awaitReply := sendRequest(from.ch, tt.reqType, tt.wantReply, tt.payload)

			forwarded := recvForwardedReq(t, to.requests, tt.reqType)
			assert.Equal(t, tt.wantReply, forwarded.WantReply)
			assert.Equal(t, tt.payload, forwarded.Payload)

			if tt.wantReply {
				require.NoError(t, forwarded.Reply(tt.replyOK, nil))
			}

			ok, err := awaitReply(t)
			require.NoError(t, err)
			assert.Equal(t, tt.replyOK, ok)

			channels.close(t, done)
		})
	}
}

func TestChannelPair_RequestForwardFailure(t *testing.T) {
	// On a session channel the gate keeps the copiers un-started, so closing the target
	// cannot race the failure reply against a concurrent source teardown.
	channels := newProxyChannels(t, "session")
	channels.sessionStartTimeout = 300 * time.Millisecond

	// Kill the target before serving so the forward deterministically fails.
	require.NoError(t, channels.server.ch.Close())
	waitReqChanClosed(t, channels.proxyUpstream.requests)

	done := channels.serve(t)

	ok, err := sendRequest(channels.client.ch, "shell", true, nil)(t)
	require.NoError(t, err)
	assert.False(t, ok, "source must get a failure reply when the forward fails")

	// The shell forward failed, so handleRequest never signals session-start; the session
	// gate in serve() never opens, and serve() can only return via sessionStartTimeout.
	waitServeDone(t, done)
}

func TestChannelPair_Teardown(t *testing.T) {
	tests := []struct {
		name             string
		clientHalfCloses bool
	}{
		{name: "client half-closes first", clientHalfCloses: true},
		{name: "server half-closes first", clientHalfCloses: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			channels := newProxyChannels(t, "direct-tcpip")
			done := channels.serve(t)

			initiator, other := channels.client, channels.server
			if !tt.clientHalfCloses {
				initiator, other = channels.server, channels.client
			}

			_, err := initiator.ch.Write([]byte("last-bytes"))
			require.NoError(t, err)
			require.NoError(t, initiator.ch.CloseWrite())

			// The other peer drains the remaining bytes, then sees EOF, while its request
			// stream stays open.
			assert.Equal(t, "last-bytes", string(readInFull(t, other.ch, len("last-bytes"))))
			assertEOF(t, other.ch)

			// The request stream survives the half-close: a request sent after EOF still arrives.
			_, err = other.ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
			require.NoError(t, err)

			recvForwardedReq(t, initiator.requests, "exit-status")

			// Full close propagates: the initiator sees EOF, its request stream closes, and
			// serve() returns.
			require.NoError(t, other.ch.Close())
			assertEOF(t, initiator.ch)
			waitReqChanClosed(t, initiator.requests)
			waitServeDone(t, done)
		})
	}
}

func TestChannelPair_TeardownTimeout(t *testing.T) {
	channels := newProxyChannels(t, "direct-tcpip")
	channels.channelCloseTimeout = 300 * time.Millisecond
	done := channels.serve(t)

	start := time.Now()

	require.NoError(t, channels.client.ch.CloseWrite())
	assertEOF(t, channels.server.ch)

	// The server never closes after EOF: the proxy force-closes the channel after
	// channelCloseTimeout instead of waiting forever.
	waitServeDone(t, done)
	assert.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
	waitReqChanClosed(t, channels.server.requests)
}

func TestChannelPair_PeerAbortMidTransfer(t *testing.T) {
	channels := newProxyChannels(t, "direct-tcpip")
	done := channels.serve(t)

	writeResult := make(chan error, 1)

	go func() {
		// Send more than the combined channel windows: the write exhausts the flow-control
		// window and blocks here with the transfer still in flight (the copier parked
		// mid-write), so it must run off the test goroutine.
		payload := bytes.Repeat([]byte("x"), 8<<20)

		_, err := channels.client.ch.Write(payload)
		writeResult <- err
	}()

	// Receive a little to prove the transfer is live, then abort abruptly.
	readInFull(t, channels.server.ch, 1024)
	require.NoError(t, channels.server.ch.Close())

	// The blocked transfer unblocks, the sender sees the abort, and teardown still completes.
	select {
	case err := <-writeResult:
		require.Error(t, err, "the aborted transfer must surface an error to the sender")
	case <-time.After(testTimeout):
		t.Fatal("sender still blocked after the peer aborted")
	}

	assertEOF(t, channels.client.ch)
	waitServeDone(t, done)
}
