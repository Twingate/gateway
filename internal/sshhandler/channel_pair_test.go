// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"gateway/internal/sessionrecorder"
)

// mockRecorder is a mock sessionrecorder.Recorder. serve() never calls IsHeaderWritten, so it
// returns a fixed value; the rest record their calls via testify for assertion.
type mockRecorder struct {
	mock.Mock
}

func (m *mockRecorder) WriteHeader(h sessionrecorder.AsciicastHeader) error {
	return m.Called(h).Error(0)
}

func (m *mockRecorder) WriteOutputEvent(data []byte) error {
	return m.Called(data).Error(0)
}

func (m *mockRecorder) WriteResizeEvent(width int, height int) error {
	return m.Called(width, height).Error(0)
}

func (m *mockRecorder) IsHeaderWritten() bool {
	return false
}

func (m *mockRecorder) Stop() {
	m.Called()
}

// mockSessionRecorderFactory is a mock SessionRecorderFactory.
type mockSessionRecorderFactory struct {
	mock.Mock
}

func (m *mockSessionRecorderFactory) NewRecorder(logger *zap.Logger) sessionrecorder.Recorder {
	//revive:disable-next-line:unchecked-type-assertion
	return m.Called(logger).Get(0).(sessionrecorder.Recorder)
}

// channelEnds is one side of a single SSH channel for a test to drive.
type channelEnds struct {
	channel  ssh.Channel
	requests <-chan *ssh.Request
}

// newGatewayChannelPair wires a real SSHChannelPair over two loopback SSH connections, mirroring
// production roles: the gateway accepts the source "session" channel opened by the downstream client
// and opens the target channel that the upstream server accepts. It returns the two test-driven far
// ends (downstream client + upstream server) and the wired pair whose serve() the test runs.
func newGatewayChannelPair(t *testing.T, logger *zap.Logger) (downstreamFar, upstreamFar channelEnds, pair *SSHChannelPair) {
	t.Helper()

	downstreamClient, downstreamServer := newSSHConnEnds(t)
	upstreamClient, upstreamServer := newSSHConnEnds(t)

	// Connection-level requests are unused; drain them so the mux never blocks.
	go ssh.DiscardRequests(downstreamClient.requests)
	go ssh.DiscardRequests(downstreamServer.requests)
	go ssh.DiscardRequests(upstreamClient.requests)
	go ssh.DiscardRequests(upstreamServer.requests)

	// Source: downstream client opens, gateway (downstream server) accepts.
	sourceGateway := acceptChannel(t, downstreamServer)

	dsCh, dsReqs, err := downstreamClient.conn.OpenChannel("session", nil)
	require.NoError(t, err)

	downstreamFar = channelEnds{channel: dsCh, requests: dsReqs}
	source := <-sourceGateway

	// Target: gateway (upstream client) opens, upstream server accepts.
	upstreamGateway := acceptChannel(t, upstreamServer)

	tgtCh, tgtReqs, err := upstreamClient.conn.OpenChannel("session", nil)
	require.NoError(t, err)

	upstreamFar = channelEnds{channel: tgtCh, requests: tgtReqs}
	target := <-upstreamGateway

	pair = NewSSHChannelPair(
		logger,
		&sshChannelContext{
			sshContext:  testSSHContext,
			channelID:   "test-channel-id",
			channelType: "session",
			sourceLabel: "downstream",
			targetLabel: "upstream",
		},
		"testuser",
		source.channel, source.requests,
		target.channel, target.requests,
	)

	return downstreamFar, upstreamFar, pair
}

// acceptChannel accepts the next incoming channel on conn in a goroutine, since OpenChannel on the
// far end blocks until the channel is accepted.
func acceptChannel(t *testing.T, conn sshConn) <-chan channelEnds {
	t.Helper()

	accepted := make(chan channelEnds, 1)

	go func() {
		newChannel, ok := <-conn.newChannels
		if !ok {
			return
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}

		accepted <- channelEnds{channel: channel, requests: requests}
	}()

	return accepted
}

// recvForwardedReq reads the next request from reqs (with a timeout) and replies true when the
// request wants a reply, so the gateway's blocking forwardRequest can complete.
func recvForwardedReq(t *testing.T, reqs <-chan *ssh.Request) *ssh.Request {
	t.Helper()

	select {
	case req := <-reqs:
		if req.WantReply {
			_ = req.Reply(true, nil)
		}

		return req
	case <-time.After(2 * time.Second):
		t.Fatal("expected a forwarded request but none arrived")

		return nil
	}
}

// sendAndAssertForward sends a request on from and asserts the gateway forwards it to the to chan
// preserving type, payload, and WantReply. WantReply sends run in a goroutine because they block
// until the forwarded request is replied to.
func sendAndAssertForward(t *testing.T, from ssh.Channel, to <-chan *ssh.Request, reqType string, wantReply bool, payload []byte) {
	t.Helper()

	sendDone := make(chan struct{})

	go func() {
		defer close(sendDone)

		_, err := from.SendRequest(reqType, wantReply, payload)
		assert.NoError(t, err)
	}()

	req := recvForwardedReq(t, to)

	assert.Equal(t, reqType, req.Type)
	assert.Equal(t, wantReply, req.WantReply)

	if len(payload) == 0 {
		assert.Empty(t, req.Payload)
	} else {
		assert.Equal(t, payload, req.Payload)
	}

	select {
	case <-sendDone:
	case <-time.After(2 * time.Second):
		t.Fatal("forwarded request send did not complete")
	}
}

func TestDefaultSessionRecorderFactory_NewRecorder(t *testing.T) {
	rec := (&DefaultSessionRecorderFactory{}).NewRecorder(zap.NewNop())
	assert.NotNil(t, rec)
}

// TestSSHChannelPair_serve_WindowChangeWithoutRecorder verifies a window-change on a session with no
// active recorder is handled gracefully (the onWindowChange callback guards against a nil recorder).
func TestSSHChannelPair_serve_WindowChangeWithoutRecorder(t *testing.T) {
	originalEOFTimeout, originalCloseTimeout := channelEOFTimeout, channelCloseTimeout
	channelEOFTimeout, channelCloseTimeout = 100*time.Millisecond, 100*time.Millisecond

	defer func() { channelEOFTimeout, channelCloseTimeout = originalEOFTimeout, originalCloseTimeout }()

	factory := &mockSessionRecorderFactory{}

	downstreamFar, upstreamFar, pair := newGatewayChannelPair(t, zap.NewNop())
	pair.recorderFactory = factory

	done := make(chan struct{})

	go func() {
		defer close(done)

		pair.serve()
	}()

	// A subsystem session does not create a recorder.
	subsystemPayload := ssh.Marshal(subsystemReq{Name: "sftp"})
	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, requestTypeSubsystem, true, subsystemPayload)

	// Without the nil-recorder guard, handling this window-change would panic and crash serve().
	windowChangePayload := ssh.Marshal(windowChangeReq{WidthColumns: 100, HeightRows: 44})
	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, requestTypeWindowChange, false, windowChangePayload)

	require.NoError(t, upstreamFar.channel.Close())
	require.NoError(t, downstreamFar.channel.Close())

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve() did not return")
	}

	factory.AssertNotCalled(t, "NewRecorder")
}

func TestSSHChannelPair_serve_ShellRecording(t *testing.T) {
	// Keep teardown fast once the channels close.
	originalEOFTimeout, originalCloseTimeout := channelEOFTimeout, channelCloseTimeout
	channelEOFTimeout, channelCloseTimeout = 100*time.Millisecond, 100*time.Millisecond

	defer func() { channelEOFTimeout, channelCloseTimeout = originalEOFTimeout, originalCloseTimeout }()

	rec := &mockRecorder{}
	rec.On("WriteHeader", mock.MatchedBy(func(h sessionrecorder.AsciicastHeader) bool {
		return h.Version == 2 &&
			h.User == "testuser" &&
			h.Width == 80 &&
			h.Height == 24 &&
			h.Command == requestTypeShell
	})).Return(nil)
	rec.On("WriteOutputEvent", mock.MatchedBy(func(data []byte) bool {
		return bytes.Equal(data, []byte("filename.txt"))
	})).Return(nil)
	rec.On("WriteResizeEvent", 100, 44).Return(nil)
	rec.On("Stop").Return()

	factory := &mockSessionRecorderFactory{}
	factory.On("NewRecorder", mock.Anything).Return(rec)

	downstreamFar, upstreamFar, pair := newGatewayChannelPair(t, zap.NewNop())
	pair.recorderFactory = factory

	done := make(chan struct{})

	go func() {
		defer close(done)

		pair.serve()
	}()

	// pty-req carries the terminal dimensions used in the asciinema header.
	ptyPayload := ssh.Marshal(ptyReq{WidthColumns: 80, HeightRows: 24})
	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, requestTypePty, true, ptyPayload)

	// shell starts the session and triggers recording.
	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, requestTypeShell, true, nil)

	// Data target->source is tapped into the recording. Reading it back also confirms the copier
	// (and therefore the recorder) is running, so the following window-change is recorded.
	_, err := upstreamFar.channel.Write([]byte("filename.txt"))
	require.NoError(t, err)

	buf := make([]byte, len("filename.txt"))
	_, err = io.ReadFull(downstreamFar.channel, buf)
	require.NoError(t, err)
	assert.Equal(t, []byte("filename.txt"), buf)

	// window-change is recorded as a resize event now that the recorder exists.
	windowChangePayload := ssh.Marshal(windowChangeReq{WidthColumns: 100, HeightRows: 44})
	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, requestTypeWindowChange, false, windowChangePayload)

	// Data source->target proves the other copy direction.
	_, err = downstreamFar.channel.Write([]byte("ls\n"))
	require.NoError(t, err)

	srcBuf := make([]byte, len("ls\n"))
	_, err = io.ReadFull(upstreamFar.channel, srcBuf)
	require.NoError(t, err)
	assert.Equal(t, []byte("ls\n"), srcBuf)

	// exit-status is forwarded target->source.
	_, err = upstreamFar.channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
	require.NoError(t, err)

	exitReq := recvForwardedReq(t, downstreamFar.requests)
	assert.Equal(t, "exit-status", exitReq.Type)

	// Closing both far ends EOFs both copy directions so serve() returns and rec.Stop() runs.
	require.NoError(t, upstreamFar.channel.Close())
	require.NoError(t, downstreamFar.channel.Close())

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve() did not return")
	}

	factory.AssertExpectations(t)
	rec.AssertExpectations(t)
}

func TestSSHChannelPair_serve_NonShellNoRecording(t *testing.T) {
	originalEOFTimeout, originalCloseTimeout := channelEOFTimeout, channelCloseTimeout
	channelEOFTimeout, channelCloseTimeout = 100*time.Millisecond, 100*time.Millisecond

	defer func() { channelEOFTimeout, channelCloseTimeout = originalEOFTimeout, originalCloseTimeout }()

	factory := &mockSessionRecorderFactory{}

	downstreamFar, upstreamFar, pair := newGatewayChannelPair(t, zap.NewNop())
	pair.recorderFactory = factory

	done := make(chan struct{})

	go func() {
		defer close(done)

		pair.serve()
	}()

	// subsystem starts the session but must not trigger recording.
	subsystemPayload := ssh.Marshal(subsystemReq{Name: "sftp"})
	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, requestTypeSubsystem, true, subsystemPayload)

	require.NoError(t, upstreamFar.channel.Close())
	require.NoError(t, downstreamFar.channel.Close())

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve() did not return")
	}

	factory.AssertNotCalled(t, "NewRecorder")
}

func TestSSHChannelPair_serve_SessionStartTimeout(t *testing.T) {
	originalStartTimeout := sessionStartTimeout
	sessionStartTimeout = 50 * time.Millisecond

	defer func() { sessionStartTimeout = originalStartTimeout }()

	factory := &mockSessionRecorderFactory{}

	// No session-start request is ever sent, so serve() must give up after sessionStartTimeout.
	_, _, pair := newGatewayChannelPair(t, zap.NewNop())
	pair.recorderFactory = factory

	done := make(chan struct{})

	go func() {
		defer close(done)

		pair.serve()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serve() did not return after the session-start timeout")
	}

	factory.AssertNotCalled(t, "NewRecorder")
}
