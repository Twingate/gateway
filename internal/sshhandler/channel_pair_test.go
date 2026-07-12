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
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/ssh"

	"gateway/internal/sessionrecorder"
)

// shortTimeout shrinks the proxy's timeout knobs so their firing path runs fast in tests.
const shortTimeout = 50 * time.Millisecond

func TestChannelPair_ForwardsData(t *testing.T) {
	channels := newProxyChannels(t, "direct-tcpip")
	done := channels.serve(t)

	// No session gate for non-"session" channel types: both directions flow immediately,
	// written concurrently before either side reads.
	_, err := channels.source.ch.Write([]byte("from source"))
	require.NoError(t, err)

	_, err = channels.target.ch.Write([]byte("from target"))
	require.NoError(t, err)

	assert.Equal(t, "from source", string(readInFull(t, channels.target.ch, len("from source"))))
	assert.Equal(t, "from target", string(readInFull(t, channels.source.ch, len("from target"))))

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
			// callback, so this case is direction-agnostic.
			name:      "malformed payload forwarded verbatim",
			reqType:   requestTypeExec,
			payload:   []byte("not-a-valid-exec-payload"),
			wantReply: true,
			replyOK:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			channels := newProxyChannels(t, "direct-tcpip")
			done := channels.serve(t)

			from, to := channels.source, channels.target
			if tt.fromTarget {
				from, to = channels.target, channels.source
			}

			awaitReply := sendRequest(from.ch, tt.reqType, tt.wantReply, tt.payload)

			forwarded := assertSentRequest(t, to.requests, tt.reqType)
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

func TestChannelPair_RequestLogsCarryChannelExtraBothDirections(t *testing.T) {
	// The forwarding details parsed at channel open must appear on request logs for both
	// directions; the target->source handler works on a reversed copy of the channel context.
	core, logs := observer.New(zap.DebugLevel)
	channels := newProxyChannels(t, channelTypeDirectTCPIP)
	channels.logger = zap.New(core)
	channels.extra = map[string]any{"test-extra": "test-value"}
	done := channels.serve(t)

	awaitReply := sendRequest(channels.target.ch, "test-req@twingate.com", true, nil)
	forwarded := assertSentRequest(t, channels.source.requests, "test-req@twingate.com")
	require.NoError(t, forwarded.Reply(true, nil))
	_, err := awaitReply(t)
	require.NoError(t, err)

	channels.close(t, done)

	channelField, isMap := observedSSHField(t, logs, "Channel request")["channel"].(map[string]any)
	require.True(t, isMap)
	assert.Equal(t, "test-value", channelField["test-extra"])
	assert.Equal(t, labelUpstream, channelField["source"], "target-side logs swap the direction labels")
}

func TestChannelPair_RequestForwardFailure(t *testing.T) {
	// On a session channel the gate keeps the copiers un-started, so closing the target
	// cannot race the failure reply against a concurrent source teardown.
	channels := newProxyChannels(t, "session")
	channels.sessionStartTimeout = shortTimeout

	// Kill the target before serving so the forward deterministically fails.
	require.NoError(t, channels.target.ch.Close())
	waitReqChanClosed(t, channels.proxyTarget.requests)

	done := channels.serve(t)

	ok, err := sendRequest(channels.source.ch, requestTypeShell, true, nil)(t)
	require.NoError(t, err)
	assert.False(t, ok, "source must get a failure reply when the forward fails")

	// The shell forward failed, so handleRequest never signals session-start; the session
	// gate in serve() never opens, and serve() can only return via sessionStartTimeout.
	waitDone(t, done)
}

func TestChannelPair_Teardown(t *testing.T) {
	tests := []struct {
		name             string
		sourceHalfCloses bool
	}{
		{name: "source half-closes first", sourceHalfCloses: true},
		{name: "target half-closes first", sourceHalfCloses: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			channels := newProxyChannels(t, "direct-tcpip")
			done := channels.serve(t)

			initiator, other := channels.source, channels.target
			if !tt.sourceHalfCloses {
				initiator, other = channels.target, channels.source
			}

			_, err := initiator.ch.Write([]byte("last-bytes"))
			require.NoError(t, err)
			require.NoError(t, initiator.ch.CloseWrite())

			// The other peer drains the remaining bytes, then sees EOF, while its requests
			// channel stays open.
			assert.Equal(t, "last-bytes", string(readInFull(t, other.ch, len("last-bytes"))))
			assertEOF(t, other.ch)

			// The requests channel survives the half-close: a request sent after EOF still arrives.
			_, err = other.ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
			require.NoError(t, err)

			assertSentRequest(t, initiator.requests, "exit-status")

			// Full close propagates: the initiator sees EOF, its requests channel closes, and
			// serve() returns.
			require.NoError(t, other.ch.Close())
			assertEOF(t, initiator.ch)
			waitReqChanClosed(t, initiator.requests)
			waitDone(t, done)
		})
	}
}

func TestChannelPair_EOFFlushTimeout(t *testing.T) {
	channels := newProxyChannels(t, "direct-tcpip")
	channels.channelEOFTimeout = shortTimeout
	done := channels.serve(t)

	// Block the request handler: it forwards a wantReply request to the target and waits
	// for a reply that never comes, so it cannot service the pre-EOF flush trigger.
	awaitReply := sendRequest(channels.source.ch, "test-req@twingate.com", true, nil)
	assertSentRequest(t, channels.target.requests, "test-req@twingate.com")

	start := time.Now()

	require.NoError(t, channels.source.ch.CloseWrite())

	// The flush can never complete: the proxy gives up after channelEOFTimeout and EOF
	// still reaches the target.
	assertEOF(t, channels.target.ch)
	assert.GreaterOrEqual(t, time.Since(start), shortTimeout)

	// Closing both ends unblocks the pending forward; the source's request must not be
	// left hanging.
	channels.close(t, done)

	_, _ = awaitReply(t)
}

func TestChannelPair_TeardownTimeout(t *testing.T) {
	channels := newProxyChannels(t, "direct-tcpip")
	channels.channelCloseTimeout = shortTimeout
	done := channels.serve(t)

	start := time.Now()

	require.NoError(t, channels.source.ch.CloseWrite())
	assertEOF(t, channels.target.ch)

	// The target never closes after EOF: the proxy force-closes the channel after
	// channelCloseTimeout instead of waiting forever.
	waitDone(t, done)
	assert.GreaterOrEqual(t, time.Since(start), shortTimeout)
	waitReqChanClosed(t, channels.target.requests)
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

		_, err := channels.source.ch.Write(payload)
		writeResult <- err
	}()

	// Receive a little to prove the transfer is live, then abort abruptly.
	readInFull(t, channels.target.ch, 1024)
	require.NoError(t, channels.target.ch.Close())

	// The blocked transfer unblocks, the sender sees the abort, and teardown still completes.
	select {
	case err := <-writeResult:
		require.Error(t, err, "the aborted transfer must surface an error to the sender")
	case <-time.After(testTimeout):
		t.Fatal("sender still blocked after the peer aborted")
	}

	assertEOF(t, channels.source.ch)
	waitDone(t, done)
}

func TestChannelPair_SessionWaitsForStart(t *testing.T) {
	tests := []struct {
		name    string
		reqType string
		payload []byte
	}{
		{name: "shell", reqType: requestTypeShell},
		{name: "exec", reqType: requestTypeExec, payload: ssh.Marshal(execReq{Command: "whoami"})},
		{name: "subsystem", reqType: requestTypeSubsystem, payload: ssh.Marshal(subsystemReq{Name: "sftp"})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			channels := newProxyChannels(t, "session")
			done := channels.serve(t)

			// Data written before the session starts is held back by the session gate.
			_, err := channels.source.ch.Write([]byte("early-bytes"))
			require.NoError(t, err)

			read := startRead(channels.target.ch, len("early-bytes"))

			select {
			case <-read:
				t.Fatal("data crossed the session gate before the session started")
			case <-time.After(shortTimeout):
			}

			// Forwarding the session-start request opens the gate and the held-back
			// bytes flow through.
			channels.sendRequestAwaitReply(t, tt.reqType, tt.payload)

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
	channels.sessionStartTimeout = shortTimeout

	start := time.Now()
	done := channels.serve(t)

	// No session-start request ever arrives, so this data must never be copied.
	_, err := channels.source.ch.Write([]byte("never-copied"))
	require.NoError(t, err)

	read := startRead(channels.target.ch, len("never-copied"))

	waitDone(t, done)
	assert.GreaterOrEqual(t, time.Since(start), shortTimeout)

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
	channels.sendRequestAwaitReply(t, requestTypePty, ssh.Marshal(ptyReq{Term: "xterm", WidthColumns: 80, HeightRows: 24}))
	channels.sendRequestAwaitReply(t, requestTypeShell, nil)

	// Only target->source data (terminal output) is recorded: source keystrokes
	// (source->target) must not show up as output events.
	_, err := channels.source.ch.Write([]byte("keystrokes"))
	require.NoError(t, err)
	assert.Equal(t, "keystrokes", string(readInFull(t, channels.target.ch, len("keystrokes"))))

	_, err = channels.target.ch.Write([]byte("terminal-output"))
	require.NoError(t, err)
	assert.Equal(t, "terminal-output", string(readInFull(t, channels.source.ch, len("terminal-output"))))

	// The window-change is recorded as a resize event before it is forwarded to the target; the
	// acked reply guarantees the resize was written before teardown.
	channels.sendWindowChange(t, 120, 40)

	channels.close(t, done)

	state := channels.recorder.state()
	require.NotNil(t, state.header)
	assert.Equal(t, 80, state.header.Width)
	assert.Equal(t, 24, state.header.Height)
	assert.Equal(t, requestTypeShell, state.header.Command)
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
		{name: "exec", reqType: requestTypeExec, payload: ssh.Marshal(execReq{Command: "whoami"})},
		{name: "subsystem", reqType: requestTypeSubsystem, payload: ssh.Marshal(subsystemReq{Name: "sftp"})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			channels := newProxyChannels(t, "session")
			done := channels.serve(t)

			// The session starts and data flows...
			channels.sendRequestAwaitReply(t, tt.reqType, tt.payload)

			_, err := channels.target.ch.Write([]byte("command-output"))
			require.NoError(t, err)
			assert.Equal(t, "command-output", string(readInFull(t, channels.source.ch, len("command-output"))))

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

	channels.sendRequestAwaitReply(t, requestTypeExec, ssh.Marshal(execReq{Command: "whoami"}))
	channels.sendWindowChange(t, 120, 40)

	// The session is still alive after the window-change.
	_, err := channels.target.ch.Write([]byte("still-alive"))
	require.NoError(t, err)
	assert.Equal(t, "still-alive", string(readInFull(t, channels.source.ch, len("still-alive"))))

	channels.close(t, done)
	assert.Equal(t, recorderState{}, channels.recorder.state())
}

func TestChannelPair_SessionRecorderWriteErrors(t *testing.T) {
	channels := newProxyChannels(t, "session")
	channels.recorder.headerErr = errors.New("header write failed")
	channels.recorder.resizeErr = errors.New("resize write failed")
	done := channels.serve(t)

	channels.sendRequestAwaitReply(t, requestTypePty, ssh.Marshal(ptyReq{Term: "xterm", WidthColumns: 80, HeightRows: 24}))
	channels.sendRequestAwaitReply(t, requestTypeShell, nil)
	channels.sendWindowChange(t, 120, 40)

	// Both writes failed, yet the session keeps going: output still flows and is recorded.
	_, err := channels.target.ch.Write([]byte("survives"))
	require.NoError(t, err)
	assert.Equal(t, "survives", string(readInFull(t, channels.source.ch, len("survives"))))

	channels.close(t, done)

	state := channels.recorder.state()
	assert.NotNil(t, state.header, "header write must have been attempted")
	assert.Len(t, state.resizes, 1, "resize write must have been attempted")
	assert.Equal(t, "survives", state.output)
	assert.True(t, state.stopped)
}

// proxyChannels is the channel-layer fixture: one channel proxied between two real SSH
// connections, exposing all four ends:
//
//	        source channel    +----------------------------------+  target channel
//	source <----------------> | proxySource        proxyTarget   | <----------------> target
//	                          +-------------- proxy -------------+
//
// The tests drive the far ends (source and target) and assert only there.
type proxyChannels struct {
	channelType string

	source      channel
	proxySource channel
	proxyTarget channel
	target      channel

	// recorder replaces the pair's real session recorder via a fakeRecorderFactory; its error
	// fields may be set before serve() to inject recorder write failures.
	recorder *fakeRecorder

	// logger overrides the pair's logger, for tests asserting its log output; nil uses zaptest.
	logger *zap.Logger

	// extra sets the channel context's open details, as parsed at channel open by forwardChannels.
	extra map[string]any

	// Optional per-test timeout overrides applied in serve(); zero leaves the pair's default.
	sessionStartTimeout time.Duration
	channelEOFTimeout   time.Duration
	channelCloseTimeout time.Duration
}

// newProxyChannels proxies one channel of the given type across two real SSH connections:
// the source end opens toward the proxy, and the proxy opens toward the target, mirroring
// forwardChannels. Global requests on all connection ends are discarded.
func newProxyChannels(t *testing.T, channelType string) *proxyChannels {
	t.Helper()

	sourceConn, proxySourceConn := sshPipe(t)
	proxyTargetConn, targetConn := sshPipe(t)

	for _, end := range []*connection{sourceConn, proxySourceConn, proxyTargetConn, targetConn} {
		go ssh.DiscardRequests(end.requests)
	}

	channels := &proxyChannels{channelType: channelType, recorder: &fakeRecorder{}}
	channels.source, channels.proxySource = openChannel(t, sourceConn, proxySourceConn, channelType, nil)
	channels.proxyTarget, channels.target = openChannel(t, proxyTargetConn, targetConn, channelType, nil)

	return channels
}

// serve builds an SSHChannelPair over the proxy-held ends and runs its serve() in the
// background; the returned channel closes when serve returns.
func (p *proxyChannels) serve(t *testing.T) <-chan struct{} {
	t.Helper()

	logger := p.logger
	if logger == nil {
		logger = zaptest.NewLogger(t)
	}

	pair := NewSSHChannelPair(
		logger,
		newSSHChannelContext(testSSHContext, p.channelType, labelDownstream, labelUpstream, p.extra),
		"testuser",
		p.proxySource,
		p.proxyTarget,
	)
	pair.recorderFactory = &fakeRecorderFactory{recorder: p.recorder}

	if p.sessionStartTimeout != 0 {
		pair.sessionStartTimeout = p.sessionStartTimeout
	}

	if p.channelEOFTimeout != 0 {
		pair.channelEOFTimeout = p.channelEOFTimeout
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

// close closes the source and target ends and waits for serve() to finish.
func (p *proxyChannels) close(t *testing.T, done <-chan struct{}) {
	t.Helper()

	_ = p.source.ch.Close()
	_ = p.target.ch.Close()

	waitDone(t, done)
}

// sendRequestAwaitReply sends a WantReply request from the source, replies success at the target,
// and requires the success reply to round-trip. The reply also guarantees the proxy finished
// handling the request (e.g. a session gate opened or a resize was recorded).
func (p *proxyChannels) sendRequestAwaitReply(t *testing.T, reqType string, payload []byte) {
	t.Helper()

	awaitReply := sendRequest(p.source.ch, reqType, true, payload)

	forwarded := assertSentRequest(t, p.target.requests, reqType)
	require.NoError(t, forwarded.Reply(true, nil))

	ok, err := awaitReply(t)
	require.NoError(t, err)
	require.True(t, ok, "%q request must succeed", reqType)
}

// sendWindowChange sends a window-change and waits for the proxy to finish handling it; the
// acknowledged reply guarantees the resize was recorded before it returns.
func (p *proxyChannels) sendWindowChange(t *testing.T, width, height uint32) {
	t.Helper()

	p.sendRequestAwaitReply(t, requestTypeWindowChange, ssh.Marshal(windowChangeReq{
		WidthColumns: width, HeightRows: height,
	}))
}

// sendRequest sends a channel request from a background goroutine, since SendRequest with
// WantReply blocks until the far end (the test itself) replies. It returns a function that blocks
// for the (ok, err) result, failing the test if none arrives within testTimeout.
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

// waitReqChanClosed asserts the requests channel closes within testTimeout without delivering
// another request.
func waitReqChanClosed(t *testing.T, reqs <-chan *ssh.Request) {
	t.Helper()

	select {
	case req, ok := <-reqs:
		require.False(t, ok, "expected requests channel to close, got request %v", req)
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for requests channel to close")
	}
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
