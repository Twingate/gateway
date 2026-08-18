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

// auditIgnoredChannelRequests holds the request types with no audit value. Any type not
// listed, including unrecognized custom ones, is audited, so an unusual request stays visible.
var auditIgnoredChannelRequests = map[string]bool{
	requestTypePty:          true,
	requestTypeWindowChange: true,
	"signal":                true,
	"xon-xoff":              true,
	"break":                 true,
	"exit-status":           true,
	"exit-signal":           true,
}

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
		h.logger.Error("Failed to parse channel request",
			zap.Any("ssh", h.sshChannelCtx.withRequest(req.Type, nil)),
			zap.Error(err))
	}
}

func (h *SSHRequestHandler) handleRequest(req *ssh.Request, sessionSignals SSHSessionSignals) {
	accepted, startSession, command := h.forwardRequest(req)

	// Reply before signaling session start: the signal unblocks serve() and lets upstream
	// data flow to the client, which must not reach the client before the request reply.
	if err := req.Reply(accepted, nil); err != nil {
		h.logger.Error("Failed to reply to channel request",
			zap.Any("ssh", h.sshChannelCtx.withRequest(req.Type, nil)), zap.Error(err))
	}

	if startSession {
		h.sessionStarted = true

		sessionSignals.started <- command

		close(sessionSignals.started)
	}
}

// forwardRequest forwards a channel request to the target channel and reports whether the target
// accepted it, along with the command to start a session with when the request starts one.
func (h *SSHRequestHandler) forwardRequest(req *ssh.Request) (accepted, startSession bool, command string) {
	// A shell, exec, or subsystem request starts the session
	// see: https://datatracker.ietf.org/doc/html/rfc4254#section-6.5
	isSessionStartReq := false
	extra := map[string]any{}

	// logger derives the fields on each call so every log line carries the detail accumulated
	// in extra so far.
	logger := func() *zap.Logger {
		return h.logger.With(zap.Any("ssh", h.sshChannelCtx.withRequest(req.Type, extra)))
	}

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
		logger().Warn("SSH channel request rejected: duplicate session start")

		return false, false, ""
	}

	accepted, err := h.targetChannel.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		logger().Error("Failed to forward channel request", zap.Error(err))

		return false, false, ""
	}

	// SendRequest's accepted result is meaningless when no reply was asked for.
	if req.WantReply {
		extra["accepted"] = accepted
	}

	if auditIgnoredChannelRequests[req.Type] {
		logger().Debug("SSH channel request")
	} else {
		logger().Info("SSH channel request")
	}

	// A session starts only when the target accepted the request; without WantReply there is
	// no confirmation and the session starts unconditionally (RFC 4254, Section 6.5).
	startSession = isSessionStartReq && (accepted || !req.WantReply)

	return accepted, startSession, command
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
