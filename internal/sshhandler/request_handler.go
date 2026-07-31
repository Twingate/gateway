// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	requestTypePty          = "pty-req"
	requestTypeShell        = "shell"
	requestTypeExec         = "exec"
	requestTypeSubsystem    = "subsystem"
	requestTypeWindowChange = "window-change"
)

type SSHSessionSignals struct {
	started  chan string // The command that started the session
	finished chan struct{}
}

type SSHRequestHandlerFlushTrigger struct {
	cb func()
}

// SSH pty request structure
// see: https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
type ptyReq struct {
	Term         string
	WidthColumns uint32
	HeightRows   uint32
	WidthPixels  uint32
	HeightPixels uint32
	Modelist     string
}

// SSH exec request structure
// see: https://datatracker.ietf.org/doc/html/rfc4254#section-6.5
type execReq struct {
	Command string
}

// SSH subsystem request structure
// see: https://datatracker.ietf.org/doc/html/rfc4254#section-6.5
type subsystemReq struct {
	Name string
}

// SSH window-change request structure
// see: https://datatracker.ietf.org/doc/html/rfc4254#section-6.7
type windowChangeReq struct {
	WidthColumns uint32
	HeightRows   uint32
	WidthPixels  uint32
	HeightPixels uint32
}

// parseRequestPayload unmarshals request payload and logs error if parsing fails.
func (h *SSHRequestHandler) parseRequestPayload(req *ssh.Request, target any) {
	if err := ssh.Unmarshal(req.Payload, target); err != nil {
		h.logger.Error("Failed to parse "+req.Type+" request",
			zap.Any("ssh", h.sshChannelCtx.withRequest(req.Type, nil)),
			zap.Error(err))
	}
}

// handleRequest processes and forwards a single SSH request, returning session info if applicable.
func (h *SSHRequestHandler) handleRequest(req *ssh.Request, sessionSignals SSHSessionSignals) {
	// A shell, exec, or subsystem request starts the session
	// see: https://datatracker.ietf.org/doc/html/rfc4254#section-6.5
	isSessionStartReq := false
	command := ""
	extra := map[string]any{}

	// logger derives the fields on each call so every log line carries the detail accumulated
	// in extra so far.
	logger := func() *zap.Logger {
		return h.logger.With(zap.Any("ssh", h.sshChannelCtx.withRequest(req.Type, extra)))
	}

	var (
		accepted bool
		err      error
	)

	// Reply exactly once, on every path; early returns leave the default, which rejects the
	// request.
	defer func() {
		if err := req.Reply(accepted, nil); err != nil {
			logger().Error("Failed to reply to request", zap.Error(err))
		}
	}()

	switch req.Type {
	case requestTypePty:
		var ptyReq ptyReq
		h.parseRequestPayload(req, &ptyReq)

		if h.onPtyRequest != nil {
			h.onPtyRequest(ptyReq)
		}
	case requestTypeShell:
		isSessionStartReq = true
		command = req.Type
	case requestTypeExec:
		isSessionStartReq = true

		var execReq execReq
		h.parseRequestPayload(req, &execReq)

		command = req.Type + " " + execReq.Command
		extra["command"] = execReq.Command
	case requestTypeSubsystem:
		isSessionStartReq = true

		var subsystemReq subsystemReq
		h.parseRequestPayload(req, &subsystemReq)

		command = req.Type + " " + subsystemReq.Name
		extra["name"] = subsystemReq.Name
	case requestTypeWindowChange:
		var windowChangeReq windowChangeReq
		h.parseRequestPayload(req, &windowChangeReq)

		if h.onWindowChange != nil {
			h.onWindowChange(windowChangeReq)
		}
	default:
		// No special handling
	}

	// A channel runs at most one shell, exec, or subsystem request (RFC 4254, Section 6.5).
	// Reject duplicates without forwarding: signaling a second session start would send on
	// the already-closed started channel.
	if isSessionStartReq && h.sessionStarted {
		logger().Warn("Rejecting duplicate session start request")

		return
	}

	accepted, err = h.targetChannel.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		logger().Error("Failed to forward request", zap.Error(err))

		return
	}

	// SendRequest's accepted result is meaningless when no reply was asked for.
	if req.WantReply {
		extra["accepted"] = accepted
	}

	logger().Info("SSH channel request")

	// A session starts only when the target accepted the request; without WantReply there is
	// no confirmation and the session starts unconditionally (RFC 4254, Section 6.5).
	if isSessionStartReq && (accepted || !req.WantReply) {
		h.sessionStarted = true

		sessionSignals.started <- command

		close(sessionSignals.started)
	}
}

type SSHRequestHandler struct {
	logger *zap.Logger

	// SSH channel-level audit context for structured logging
	sshChannelCtx *sshChannelContext

	// Trigger used to flush any pending requests
	flushTrigger <-chan SSHRequestHandlerFlushTrigger

	// Go Channel to process incoming SSH channel requests from
	sourceRequestChan <-chan *ssh.Request

	// Target SSH channel to forward SSH channel requests to
	targetChannel ssh.Channel

	// Whether a session-start request (shell, exec, or subsystem) has already started a session;
	// only the handleRequests goroutine touches it
	sessionStarted bool

	// Optional callback for when a pty request is received providing the width and height of the terminal
	onPtyRequest func(req ptyReq)

	// Optional callback for when a window-change request is received
	onWindowChange func(req windowChangeReq)
}

// Processes SSH channel requests from the source go channel and forwards them to the target SSH channel
// on a separate goroutine.
func (h *SSHRequestHandler) handleRequests() SSHSessionSignals {
	sessionSignals := SSHSessionSignals{
		started:  make(chan string, 1),
		finished: make(chan struct{}),
	}

	go func() {
		defer closeOnPanic(h.logger, func() { _ = h.targetChannel.Close() })
		defer close(sessionSignals.finished)

		for {
			select {
			case req, ok := <-h.sourceRequestChan:
				if !ok {
					// Request channel closed, we are finished
					return
				}
				// Forward the request
				h.handleRequest(req, sessionSignals)

			case trigger, ok := <-h.flushTrigger:
				if !ok {
					h.logger.Error("Flush trigger channel closed prematurely",
						zap.Any("ssh", h.sshChannelCtx.baseFields()))

					return
				}

				// Drain any immediately available requests
				draining := true
				for draining {
					select {
					case req, ok := <-h.sourceRequestChan:
						if !ok {
							// Request channel closed, we are finished
							draining = false
						} else {
							// Forward the request
							h.handleRequest(req, sessionSignals)
						}
					// Make select non-blocking, will enter here when there are no more requests to drain
					default:
						draining = false
					}
				}
				// Call the callback to signal that we have drained any pending requests
				trigger.cb()
			}
		}
	}()

	return sessionSignals
}
