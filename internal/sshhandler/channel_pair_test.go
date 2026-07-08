// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/crypto/ssh"

	"gateway/internal/sessionrecorder"
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

	// recorder replaces the pair's real session recorder via a fakeRecorderFactory; its error
	// fields may be set before serve() to inject recorder write failures.
	recorder *fakeRecorder

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

	channels := &proxyChannels{channelType: channelType, recorder: &fakeRecorder{}}
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
	pair.recorderFactory = &fakeRecorderFactory{recorder: p.recorder}

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

// sendAckedRequest sends a WantReply request from the client, acknowledges it at the server,
// and requires the success reply to round-trip. The reply also guarantees the proxy finished
// handling the request (e.g. a session gate opened or a resize was recorded).
func (p *proxyChannels) sendAckedRequest(t *testing.T, reqType string, payload []byte) {
	t.Helper()

	awaitReply := sendRequest(p.client.ch, reqType, true, payload)

	forwarded := recvForwardedReq(t, p.server.requests, reqType)
	require.NoError(t, forwarded.Reply(true, nil))

	ok, err := awaitReply(t)
	require.NoError(t, err)
	require.True(t, ok, "%q request must succeed", reqType)
}

// sendWindowChange sends a window-change and waits for the proxy to finish handling it; the
// acknowledged reply guarantees the resize was recorded before it returns.
func (p *proxyChannels) sendWindowChange(t *testing.T, width, height uint32) {
	t.Helper()

	p.sendAckedRequest(t, requestTypeWindowChange, ssh.Marshal(windowChangeReq{
		WidthColumns: width, HeightRows: height,
	}))
}

// fakeRecorder is a sessionrecorder.Recorder that records every call it receives and returns
// the injected errors, if any, from its write methods.
type fakeRecorder struct {
	mu sync.Mutex

	// Injected results for WriteHeader / WriteResizeEvent; the calls are recorded regardless.
	headerErr error
	resizeErr error

	header  *sessionrecorder.AsciicastHeader
	output  bytes.Buffer
	resizes []sessionrecorder.ResizeMsg
	stopped bool
}

func (r *fakeRecorder) WriteHeader(h sessionrecorder.AsciicastHeader) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.header = &h

	return r.headerErr
}

func (r *fakeRecorder) WriteOutputEvent(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.output.Write(data)

	return nil
}

func (r *fakeRecorder) WriteResizeEvent(width int, height int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.resizes = append(r.resizes, sessionrecorder.ResizeMsg{Width: width, Height: height})

	return r.resizeErr
}

func (r *fakeRecorder) IsHeaderWritten() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.header != nil
}

func (r *fakeRecorder) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.stopped = true
}

// recorderState is a point-in-time copy of everything a fakeRecorder observed; its zero value
// means the recorder was never touched.
type recorderState struct {
	header  *sessionrecorder.AsciicastHeader
	output  string
	resizes []sessionrecorder.ResizeMsg
	stopped bool
}

func (r *fakeRecorder) state() recorderState {
	r.mu.Lock()
	defer r.mu.Unlock()

	return recorderState{
		header:  r.header,
		output:  r.output.String(),
		resizes: r.resizes,
		stopped: r.stopped,
	}
}

// fakeRecorderFactory implements SessionRecorderFactory by handing out the fixture's fakeRecorder.
type fakeRecorderFactory struct {
	recorder *fakeRecorder
}

func (f *fakeRecorderFactory) NewRecorder(*zap.Logger) sessionrecorder.Recorder {
	return f.recorder
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

// startRead begins reading exactly n bytes in the background and returns a channel that
// delivers them once the read completes; the tests use it to assert that data does or does
// not arrive across the session gate.
func startRead(reader io.Reader, n int) <-chan []byte {
	out := make(chan []byte, 1)

	go func() {
		buf := make([]byte, n)
		if _, err := io.ReadFull(reader, buf); err == nil {
			out <- buf
		}
	}()

	return out
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

func TestChannelPair_SessionWaitsForStart(t *testing.T) {
	tests := []struct {
		name    string
		reqType string
		payload []byte
	}{
		{name: "shell", reqType: "shell"},
		{name: "exec", reqType: "exec", payload: ssh.Marshal(execReq{Command: "ls"})},
		{name: "subsystem", reqType: "subsystem", payload: ssh.Marshal(subsystemReq{Name: "sftp"})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			channels := newProxyChannels(t, "session")
			done := channels.serve(t)

			// Data written before the session starts is held back by the session gate.
			_, err := channels.client.ch.Write([]byte("early-bytes"))
			require.NoError(t, err)

			read := startRead(channels.server.ch, len("early-bytes"))

			select {
			case <-read:
				t.Fatal("data crossed the session gate before the session started")
			case <-time.After(100 * time.Millisecond):
			}

			// Forwarding the session-start request opens the gate and the held-back
			// bytes flow through.
			channels.sendAckedRequest(t, tt.reqType, tt.payload)

			select {
			case got := <-read:
				assert.Equal(t, "early-bytes", string(got))
			case <-time.After(testTimeout):
				t.Fatal("timed out waiting for data after session start")
			}

			channels.close(t, done)
		})
	}
}

func TestChannelPair_SessionStartTimeout(t *testing.T) {
	channels := newProxyChannels(t, "session")
	channels.sessionStartTimeout = 300 * time.Millisecond

	start := time.Now()
	done := channels.serve(t)

	// No session-start request ever arrives, so this data must never be copied.
	_, err := channels.client.ch.Write([]byte("never-copied"))
	require.NoError(t, err)

	read := startRead(channels.server.ch, len("never-copied"))

	waitServeDone(t, done)
	assert.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)

	select {
	case <-read:
		t.Fatal("data was copied even though the session never started")
	default:
	}

	assert.Equal(t, recorderState{}, channels.recorder.state(), "no session => no recorder")

	channels.close(t, done)
}

func TestChannelPair_SessionShellRecording(t *testing.T) {
	channels := newProxyChannels(t, "session")
	done := channels.serve(t)

	// pty-req precedes shell by convention; its dimensions seed the asciinema header.
	channels.sendAckedRequest(t, "pty-req", ssh.Marshal(ptyReq{Term: "xterm", WidthColumns: 80, HeightRows: 24}))
	channels.sendAckedRequest(t, "shell", nil)

	// Only upstream->downstream data (terminal output) is recorded: client keystrokes
	// must not show up as output events.
	_, err := channels.client.ch.Write([]byte("keystrokes"))
	require.NoError(t, err)
	assert.Equal(t, "keystrokes", string(readInFull(t, channels.server.ch, len("keystrokes"))))

	_, err = channels.server.ch.Write([]byte("terminal-output"))
	require.NoError(t, err)
	assert.Equal(t, "terminal-output", string(readInFull(t, channels.client.ch, len("terminal-output"))))

	// The window-change is recorded as a resize event before it is forwarded upstream; the
	// acked reply guarantees the resize was written before teardown.
	channels.sendWindowChange(t, 120, 40)

	channels.close(t, done)

	state := channels.recorder.state()
	require.NotNil(t, state.header)
	assert.Equal(t, 80, state.header.Width)
	assert.Equal(t, 24, state.header.Height)
	assert.Equal(t, "shell", state.header.Command)
	assert.Equal(t, "testuser", state.header.User)
	assert.Equal(t, "terminal-output", state.output)
	assert.Equal(t, []sessionrecorder.ResizeMsg{{Width: 120, Height: 40}}, state.resizes)
	assert.True(t, state.stopped, "recorder must be stopped on teardown")
}

func TestChannelPair_SessionNonShellNoRecording(t *testing.T) {
	tests := []struct {
		name    string
		reqType string
		payload []byte
	}{
		{name: "exec", reqType: "exec", payload: ssh.Marshal(execReq{Command: "ls"})},
		{name: "subsystem", reqType: "subsystem", payload: ssh.Marshal(subsystemReq{Name: "sftp"})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			channels := newProxyChannels(t, "session")
			done := channels.serve(t)

			// The session starts and data flows...
			channels.sendAckedRequest(t, tt.reqType, tt.payload)

			_, err := channels.server.ch.Write([]byte("command-output"))
			require.NoError(t, err)
			assert.Equal(t, "command-output", string(readInFull(t, channels.client.ch, len("command-output"))))

			channels.close(t, done)

			// ...but nothing is recorded: only shell sessions create a recorder.
			assert.Equal(t, recorderState{}, channels.recorder.state())
		})
	}
}

func TestChannelPair_SessionWindowChangeWithoutRecorder(t *testing.T) {
	// Only shell sessions get a recorder, so on an exec session the resize callback holds a
	// nil recorder. A window-change must hit that nil guard and forward cleanly rather than
	// dereference the missing recorder and panic.
	channels := newProxyChannels(t, "session")
	done := channels.serve(t)

	channels.sendAckedRequest(t, "exec", ssh.Marshal(execReq{Command: "top"}))
	channels.sendWindowChange(t, 120, 40)

	// The session is still alive after the window-change.
	_, err := channels.server.ch.Write([]byte("still-alive"))
	require.NoError(t, err)
	assert.Equal(t, "still-alive", string(readInFull(t, channels.client.ch, len("still-alive"))))

	channels.close(t, done)
	assert.Equal(t, recorderState{}, channels.recorder.state())
}

func TestChannelPair_SessionRecorderWriteErrors(t *testing.T) {
	channels := newProxyChannels(t, "session")
	channels.recorder.headerErr = errors.New("header write failed")
	channels.recorder.resizeErr = errors.New("resize write failed")
	done := channels.serve(t)

	channels.sendAckedRequest(t, "pty-req", ssh.Marshal(ptyReq{Term: "xterm", WidthColumns: 80, HeightRows: 24}))
	channels.sendAckedRequest(t, "shell", nil)
	channels.sendWindowChange(t, 120, 40)

	// Both writes failed, yet the session keeps going: output still flows and is recorded.
	_, err := channels.server.ch.Write([]byte("survives"))
	require.NoError(t, err)
	assert.Equal(t, "survives", string(readInFull(t, channels.client.ch, len("survives"))))

	channels.close(t, done)

	state := channels.recorder.state()
	assert.NotNil(t, state.header, "header write must have been attempted")
	assert.Len(t, state.resizes, 1, "resize write must have been attempted")
	assert.Equal(t, "survives", state.output)
	assert.True(t, state.stopped)
}
