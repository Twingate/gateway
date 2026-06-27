// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"io"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"gateway/internal/sessionrecorder"
)

var sessionStartTimeout = 10 * time.Second

// SessionRecorderFactory creates session recorders.
type SessionRecorderFactory interface {
	NewRecorder(logger *zap.Logger) sessionrecorder.Recorder
}

// DefaultSessionRecorderFactory implements SessionRecorderFactory.
type DefaultSessionRecorderFactory struct{}

func (f *DefaultSessionRecorderFactory) NewRecorder(logger *zap.Logger) sessionrecorder.Recorder {
	return sessionrecorder.NewRecorder(logger)
}

// TerminalOutputRecorder is used for tapping into the raw output of a channel.
type TerminalOutputRecorder struct {
	recorder sessionrecorder.Recorder
}

func (c *TerminalOutputRecorder) Write(p []byte) (n int, err error) {
	err = c.recorder.WriteOutputEvent(p)

	return len(p), err
}

type SSHChannelPair struct {
	logger *zap.Logger

	// sshChannelCtx carries channel-level context
	sshChannelCtx *sshChannelContext

	// Source SSH channel
	sourceChannel ssh.Channel
	// Source SSH channel requests channel
	sourceChannelRequests <-chan Request

	// Target SSH channel
	targetChannel ssh.Channel
	// Target SSH channel requests channel
	targetChannelRequests <-chan Request

	// SSH username (for session recording)
	sshUsername string

	// Factory for creating session recorders
	recorderFactory SessionRecorderFactory

	ptyRequestOnce sync.Once
}

// NewSSHChannelPair creates a new SSHChannelPair with the default factories.
func NewSSHChannelPair(logger *zap.Logger, sshChannelCtx *sshChannelContext, sshUsername string, sourceChannel ssh.Channel, sourceRequests <-chan Request, targetChannel ssh.Channel, targetRequests <-chan Request) *SSHChannelPair {
	return &SSHChannelPair{
		logger:                logger,
		sshChannelCtx:         sshChannelCtx,
		sshUsername:           sshUsername,
		sourceChannel:         sourceChannel,
		sourceChannelRequests: sourceRequests,
		targetChannel:         targetChannel,
		targetChannelRequests: targetRequests,
		recorderFactory:       &DefaultSessionRecorderFactory{},
	}
}

func (c *SSHChannelPair) serve() {
	logger := c.logger.With(zap.Any("ssh", c.sshChannelCtx.baseFields()))

	var (
		rec   sessionrecorder.Recorder
		recMu sync.RWMutex
	)

	// Create default asciinema header
	asciinemaHeader := sessionrecorder.AsciicastHeader{
		Version:   2,
		Timestamp: time.Now().Unix(),
		User:      c.sshUsername,
	}

	// Handle the source channel's requests
	sourceEOFTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)
	sourceRequestHandler := &SSHRequestHandler{
		logger:            c.logger,
		sshChannelCtx:     c.sshChannelCtx,
		flushTrigger:      sourceEOFTrigger,
		sourceRequestChan: c.sourceChannelRequests,
		targetChannel:     c.targetChannel,
		onPtyRequest: func(req ptyReq) {
			// Set the asciinema header with the pty request details only once
			c.ptyRequestOnce.Do(func() {
				asciinemaHeader.Width = int(req.WidthColumns)
				asciinemaHeader.Height = int(req.HeightRows)
			})
		},
		onWindowChange: func(req windowChangeReq) {
			recMu.RLock()

			r := rec

			recMu.RUnlock()

			if r == nil {
				return
			}

			if err := r.WriteResizeEvent(int(req.WidthColumns), int(req.HeightRows)); err != nil {
				logger.Error("failed to write resize event", zap.Error(err))
			}
		},
	}
	sourceSessionSignals := sourceRequestHandler.handleRequests()

	// Handle the target channel's requests
	targetEOFTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)
	targetChannelCtx := &sshChannelContext{
		sshContext:  c.sshChannelCtx.sshContext,
		channelID:   c.sshChannelCtx.channelID,
		channelType: c.sshChannelCtx.channelType,
		sourceLabel: c.sshChannelCtx.targetLabel,
		targetLabel: c.sshChannelCtx.sourceLabel,
	}
	targetRequestHandler := &SSHRequestHandler{
		logger:            c.logger,
		sshChannelCtx:     targetChannelCtx,
		flushTrigger:      targetEOFTrigger,
		sourceRequestChan: c.targetChannelRequests,
		targetChannel:     c.sourceChannel,
		onPtyRequest:      nil,
		onWindowChange:    nil,
	}
	targetSessionSignals := targetRequestHandler.handleRequests()

	var command string

	if c.sshChannelCtx.channelType == "session" {
		// Wait for session to start from source prior to starting the data copying
		select {
		case command = <-sourceSessionSignals.started:
			logger.Debug("Source session started", zap.String("command", command))
			asciinemaHeader.Command = command
		case <-time.After(sessionStartTimeout):
			logger.Error("Timeout waiting for source session to start")

			return
		}
	}

	var processor io.Writer

	if command == requestTypeShell {
		recMu.Lock()

		rec = c.recorderFactory.NewRecorder(logger)

		recMu.Unlock()

		defer rec.Stop()

		// Write the asciinema header to the recorder
		// Note: We are relying on the convention that 'pty-req' will be sent prior to 'shell' requests,
		// so we should have already set the asciinema header with the pty request details
		// in the onPtyRequest() callback on the sourceRequestHandler
		err := rec.WriteHeader(asciinemaHeader)
		if err != nil {
			logger.Error("failed to write asciinema header", zap.Error(err))
		}

		processor = &TerminalOutputRecorder{recorder: rec}
	}

	copier := &BidirectionalCopier{
		logger: logger,
		SourceToTarget: ChannelCopyPair{
			logger:          logger,
			Src:             c.sourceChannel,
			Dst:             c.targetChannel,
			EOFTriggerCh:    sourceEOFTrigger,
			ChannelClosedCh: sourceSessionSignals.finished,
		},

		TargetToSource: ChannelCopyPair{
			logger:          logger,
			Src:             c.targetChannel,
			Dst:             c.sourceChannel,
			EOFTriggerCh:    targetEOFTrigger,
			ChannelClosedCh: targetSessionSignals.finished,
			Tap:             processor,
		},
	}

	copier.start()
}
