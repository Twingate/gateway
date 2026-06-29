// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/ssh"
)

func createPtyRequestPayload() []byte {
	ptyReq := ptyReq{
		Term:         "xterm-256color",
		WidthColumns: 80,
		HeightRows:   24,
		WidthPixels:  640,
		HeightPixels: 480,
		Modelist:     "",
	}
	payload := ssh.Marshal(ptyReq)

	return payload
}

func createExecRequestPayload(command string) []byte {
	execReq := execReq{
		Command: command,
	}
	payload := ssh.Marshal(execReq)

	return payload
}

func createSubsystemRequestPayload(name string) []byte {
	subsystemReq := subsystemReq{
		Name: name,
	}
	payload := ssh.Marshal(subsystemReq)

	return payload
}

func createWindowChangeRequestPayload() []byte {
	windowChangeReq := windowChangeReq{
		WidthColumns: 80,
		HeightRows:   24,
		WidthPixels:  640,
		HeightPixels: 480,
	}
	payload := ssh.Marshal(windowChangeReq)

	return payload
}

// newRequestHandlerEnds wires a SSHRequestHandler over real SSH channels, mirroring production roles:
// the gateway accepts the source channel opened by the downstream client (its request chan feeds the
// handler) and opens the target channel the upstream server accepts (the handler forwards onto it).
// It returns the handler (with a nop logger and no-op pty callback that tests override as needed) and
// the two test-driven far ends: downstreamFar.channel drives requests, upstreamFar.requests receives
// the forwarded ones.
func newRequestHandlerEnds(t *testing.T) (handler *SSHRequestHandler, downstreamFar, upstreamFar channelEnds) {
	t.Helper()

	downstreamClient, downstreamServer := newSSHConnEnds(t)
	upstreamClient, upstreamServer := newSSHConnEnds(t)

	// Connection-level requests are unused; drain them so the mux never blocks.
	go ssh.DiscardRequests(downstreamClient.requests)
	go ssh.DiscardRequests(downstreamServer.requests)
	go ssh.DiscardRequests(upstreamClient.requests)
	go ssh.DiscardRequests(upstreamServer.requests)

	// Source: downstream client opens, gateway (downstream server) accepts.
	sourceAccepted := acceptChannel(t, downstreamServer)

	dsCh, dsReqs, err := downstreamClient.conn.OpenChannel("session", nil)
	require.NoError(t, err)

	downstreamFar = channelEnds{channel: dsCh, requests: dsReqs}
	source := <-sourceAccepted

	// Target: gateway (upstream client) opens, upstream server accepts.
	upstreamGateway := acceptChannel(t, upstreamServer)

	tgtCh, tgtReqs, err := upstreamClient.conn.OpenChannel("session", nil)
	require.NoError(t, err)

	go ssh.DiscardRequests(tgtReqs)

	upstreamFar = <-upstreamGateway

	handler = &SSHRequestHandler{
		logger: zap.NewNop(),
		sshChannelCtx: &sshChannelContext{
			sshContext:  testSSHContext,
			channelID:   "test-channel-id",
			channelType: "session",
			sourceLabel: labelDownstream,
			targetLabel: labelUpstream,
		},
		sourceRequestChan: source.requests,
		targetChannel:     tgtCh,
		onPtyRequest:      func(_ ptyReq) {},
	}

	return handler, downstreamFar, upstreamFar
}

func TestSSHRequestHandler_handleRequests_PtyRequest(t *testing.T) {
	handler, downstreamFar, upstreamFar := newRequestHandlerEnds(t)
	core, logs := observer.New(zap.DebugLevel)
	handler.logger = zap.New(core).Named("test")

	var capturedPtyReq ptyReq

	handler.onPtyRequest = func(req ptyReq) { capturedPtyReq = req }

	signals := handler.handleRequests()

	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, requestTypePty, true, createPtyRequestPayload())

	require.NoError(t, downstreamFar.channel.Close())
	<-signals.finished

	// Verify pty request was parsed and the callback received the dimensions.
	assert.Equal(t, "xterm-256color", capturedPtyReq.Term)
	assert.Equal(t, uint32(80), capturedPtyReq.WidthColumns)
	assert.Equal(t, uint32(24), capturedPtyReq.HeightRows)

	requestLog := logs.FilterMessage("SSH channel request").All()
	assert.Len(t, requestLog, 1)

	sshField := requestLog[0].ContextMap()["ssh"].(map[string]any)
	assert.Equal(t, "pty-req", sshField["request"].(map[string]any)["type"])
}

func TestSSHRequestHandler_handleRequests_ShellRequest(t *testing.T) {
	handler, downstreamFar, upstreamFar := newRequestHandlerEnds(t)
	core, logs := observer.New(zap.DebugLevel)
	handler.logger = zap.New(core).Named("test")

	signals := handler.handleRequests()

	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, requestTypeShell, true, nil)

	// Shell starts the session.
	command := <-signals.started
	assert.Equal(t, "shell", command)

	require.NoError(t, downstreamFar.channel.Close())
	<-signals.finished

	requestLog := logs.FilterMessage("SSH channel request").All()
	assert.Len(t, requestLog, 1)

	sshField := requestLog[0].ContextMap()["ssh"].(map[string]any)
	assert.Equal(t, "shell", sshField["request"].(map[string]any)["type"])
}

func TestSSHRequestHandler_handleRequests_ExecRequest(t *testing.T) {
	handler, downstreamFar, upstreamFar := newRequestHandlerEnds(t)
	core, logs := observer.New(zap.DebugLevel)
	handler.logger = zap.New(core).Named("test")

	signals := handler.handleRequests()

	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, requestTypeExec, true, createExecRequestPayload("ls -la"))

	// Exec starts the session and carries the command.
	command := <-signals.started
	assert.Equal(t, "exec ls -la", command)

	require.NoError(t, downstreamFar.channel.Close())
	<-signals.finished

	requestLog := logs.FilterMessage("SSH channel request").All()
	assert.Len(t, requestLog, 1)

	sshField := requestLog[0].ContextMap()["ssh"].(map[string]any)
	assert.Equal(t, "exec", sshField["request"].(map[string]any)["type"])
	assert.Equal(t, "ls -la", sshField["request"].(map[string]any)["command"])
}

func TestSSHRequestHandler_handleRequests_SubsystemRequest(t *testing.T) {
	handler, downstreamFar, upstreamFar := newRequestHandlerEnds(t)
	core, logs := observer.New(zap.DebugLevel)
	handler.logger = zap.New(core).Named("test")

	signals := handler.handleRequests()

	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, requestTypeSubsystem, false, createSubsystemRequestPayload("sftp"))

	// Subsystem starts the session and carries the subsystem name.
	command := <-signals.started
	assert.Equal(t, "subsystem sftp", command)

	require.NoError(t, downstreamFar.channel.Close())
	<-signals.finished

	requestLog := logs.FilterMessage("SSH channel request").All()
	assert.Len(t, requestLog, 1)

	sshField := requestLog[0].ContextMap()["ssh"].(map[string]any)
	assert.Equal(t, "subsystem", sshField["request"].(map[string]any)["type"])
	assert.Equal(t, "sftp", sshField["request"].(map[string]any)["name"])
}

func TestSSHRequestHandler_handleRequests_WindowChangeRequest(t *testing.T) {
	handler, downstreamFar, upstreamFar := newRequestHandlerEnds(t)

	var capturedWindowChangeReq windowChangeReq

	handler.onWindowChange = func(req windowChangeReq) { capturedWindowChangeReq = req }

	signals := handler.handleRequests()

	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, requestTypeWindowChange, false, createWindowChangeRequestPayload())

	require.NoError(t, downstreamFar.channel.Close())
	<-signals.finished

	// Verify window-change request was parsed and the callback received the dimensions.
	assert.Equal(t, uint32(80), capturedWindowChangeReq.WidthColumns)
	assert.Equal(t, uint32(24), capturedWindowChangeReq.HeightRows)
}

func TestSSHRequestHandler_handleRequests_FlushTrigger(t *testing.T) {
	handler, downstreamFar, upstreamFar := newRequestHandlerEnds(t)
	flushTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)
	handler.flushTrigger = flushTrigger

	signals := handler.handleRequests()

	// A normal request is processed first.
	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, requestTypePty, true, createPtyRequestPayload())

	// The flush trigger drains pending requests and then invokes the callback.
	flushed := make(chan struct{})
	flushTrigger <- SSHRequestHandlerFlushTrigger{cb: func() { close(flushed) }}

	select {
	case <-flushed:
	case <-time.After(2 * time.Second):
		t.Fatal("flush callback was not invoked")
	}

	require.NoError(t, downstreamFar.channel.Close())
	<-signals.finished
}

func TestSSHRequestHandler_handleRequests_ChannelClosed(t *testing.T) {
	handler, downstreamFar, _ := newRequestHandlerEnds(t)

	signals := handler.handleRequests()

	// Closing the source channel closes the gateway's request chan, finishing the handler.
	require.NoError(t, downstreamFar.channel.Close())

	select {
	case <-signals.finished:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish after source channel closed")
	}
}

func TestSSHRequestHandler_handleRequests_UnknownType(t *testing.T) {
	handler, downstreamFar, upstreamFar := newRequestHandlerEnds(t)
	core, logs := observer.New(zap.DebugLevel)
	handler.logger = zap.New(core).Named("test")

	signals := handler.handleRequests()

	// An unknown request type is still forwarded but not logged as an "SSH channel request".
	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, "some-command", true, []byte("some random data"))

	require.NoError(t, downstreamFar.channel.Close())
	<-signals.finished

	requestLog := logs.FilterMessage("SSH channel request").All()
	assert.Empty(t, requestLog)
}

// TestSSHRequestHandler_parseRequestPayload_Malformed verifies a typed request whose payload cannot
// be unmarshalled is logged and still forwarded without crashing the handler.
func TestSSHRequestHandler_parseRequestPayload_Malformed(t *testing.T) {
	handler, downstreamFar, upstreamFar := newRequestHandlerEnds(t)
	core, logs := observer.New(zap.DebugLevel)
	handler.logger = zap.New(core).Named("test")

	signals := handler.handleRequests()

	// A pty-req with a truncated payload fails to unmarshal but is still forwarded verbatim.
	sendAndAssertForward(t, downstreamFar.channel, upstreamFar.requests, requestTypePty, true, []byte{0x00})

	require.NoError(t, downstreamFar.channel.Close())
	<-signals.finished

	assert.NotEmpty(t, logs.FilterMessage("Failed to parse pty-req request").All(),
		"the malformed payload should have been logged")
}

// TestSSHRequestHandler_handleRequest_ForwardError verifies that when forwarding a session-starting
// request to the target channel fails, the handler logs the failure and returns early without
// signaling that the session has started.
func TestSSHRequestHandler_handleRequest_ForwardError(t *testing.T) {
	handler, downstreamFar, _ := newRequestHandlerEnds(t)
	core, logs := observer.New(zap.DebugLevel)
	handler.logger = zap.New(core).Named("test")

	// Closing the target channel makes the forwarded SendRequest fail.
	require.NoError(t, handler.targetChannel.Close())

	signals := handler.handleRequests()

	// Send a session-starting request; forwarding fails so the started signal must not fire.
	go func() {
		_, _ = downstreamFar.channel.SendRequest(requestTypeExec, true, createExecRequestPayload("ls"))
	}()

	// The forwarding failure should be logged.
	require.Eventually(t, func() bool {
		return len(logs.FilterMessage("Failed to forward request").All()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	require.NoError(t, downstreamFar.channel.Close())
	<-signals.finished

	// The early return means the session never started.
	select {
	case <-signals.started:
		t.Fatal("session should not have started when forwarding failed")
	default:
	}
}

// TestForwardRequest_TargetSendError verifies that when forwarding to the target channel fails,
// forwardRequest replies failure to the source and returns the error.
func TestForwardRequest_TargetSendError(t *testing.T) {
	handler, downstreamFar, _ := newRequestHandlerEnds(t)

	// Closing the target channel makes the forwarded SendRequest fail.
	require.NoError(t, handler.targetChannel.Close())

	// The source sends a WantReply request and must receive a failure reply.
	replyCh := make(chan bool, 1)

	go func() {
		ok, _ := downstreamFar.channel.SendRequest(requestTypeExec, true, createExecRequestPayload("x"))
		replyCh <- ok
	}()

	req := <-handler.sourceRequestChan

	require.Error(t, forwardRequest(handler.targetChannel, req))

	select {
	case ok := <-replyCh:
		assert.False(t, ok, "source should receive a failure reply")
	case <-time.After(2 * time.Second):
		t.Fatal("source did not receive a reply")
	}
}

func TestForwardRequest_Success(t *testing.T) {
	handler, downstreamFar, upstreamFar := newRequestHandlerEnds(t)

	// Drive a real request so forwardRequest receives one whose source it can reply to.
	go func() {
		_, _ = downstreamFar.channel.SendRequest(requestTypeShell, true, nil)
	}()

	req := <-handler.sourceRequestChan

	// forwardRequest blocks until the target far end replies, so run it concurrently.
	fwdErr := make(chan error, 1)

	go func() {
		fwdErr <- forwardRequest(handler.targetChannel, req)
	}()

	forwarded := recvForwardedReq(t, upstreamFar.requests)
	assert.Equal(t, requestTypeShell, forwarded.Type)

	select {
	case err := <-fwdErr:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("forwardRequest did not complete")
	}
}
