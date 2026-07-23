// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"errors"
	"io"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	defaultChannelEOFTimeout   = 5 * time.Second
	defaultChannelCloseTimeout = 10 * time.Second
)

type ChannelCopyPair struct {
	logger *zap.Logger

	// Source channel
	Src ssh.Channel

	// Destination channel
	Dst ssh.Channel

	// Trigger for flushing any pending requests prior to EOF
	EOFTriggerCh chan<- SSHRequestHandlerFlushTrigger

	// Channel to wait for during teardown, which indicates the channel is fully closed
	ChannelClosedCh <-chan struct{}

	// Tap for recording a channel's data from Src channel
	Tap io.Writer

	// eofTimeout bounds the wait for a pending-request flush or a Src close before sending EOF.
	eofTimeout time.Duration

	// closeTimeout bounds the wait for the peer to close the channel before force-closing it.
	closeTimeout time.Duration
}

func (c *ChannelCopyPair) copy() {
	var reader io.Reader = c.Src
	if c.Tap != nil {
		reader = io.TeeReader(reader, c.Tap)
	}

	if _, err := io.Copy(c.Dst, reader); err != nil && !errors.Is(err, io.EOF) {
		c.logger.Error("io.Copy error", zap.Error(err))
	}

	// No more data to copy from Src, begin teardown logic
	// See: https://datatracker.ietf.org/doc/html/rfc4254#section-5.3
	// for how SSH Channels are closed using SSH_MSG_CHANNEL_EOF and SSH_MSG_CHANNEL_CLOSE

	c.logger.Debug("io.Copy finished, starting channel teardown")

	// Try to flush any pending requests
	eofTriggerCh := make(chan struct{}, 1)
	c.EOFTriggerCh <- SSHRequestHandlerFlushTrigger{
		cb: func() {
			eofTriggerCh <- struct{}{}
		},
	}

	select {
	case <-eofTriggerCh:
		// If Src sent EOF and the requests channel is still open,
		// we try to flush any pending requests before continuing to send SSH_MSG_CHANNEL_EOF
		c.logger.Debug("EOF triggered")
	case <-c.ChannelClosedCh:
		// If Src already closed the channel, then there's no pending requests anymore, so we can
		// send SSH_MSG_CHANNEL_EOF
		c.logger.Debug("Channel closed")
	case <-time.After(c.eofTimeout):
		// If we timeout, we proceed with teardown
		c.logger.Error("Timeout waiting for EOF trigger or channel close")
	}

	// Now that we have flushed any pending requests, we can start teardown
	// by closing the Dst channel write side (we are done writing data)
	// which sends SSH_MSG_CHANNEL_EOF
	c.logger.Debug("Closing write side on destination")

	if err := c.Dst.CloseWrite(); err != nil && !errors.Is(err, io.EOF) {
		c.logger.Error("CloseWrite failed", zap.Error(err))
	}

	// Now we should just wait for the requests channel to close, which
	// will signify that the channel is fully closed
	select {
	case <-c.ChannelClosedCh:
		c.logger.Debug("Requests channel closed")
	case <-time.After(c.closeTimeout):
		c.logger.Error("Timeout waiting for requests channel close")
	}

	// At this point, we are done with the session and the exit-status request should
	// already have been propagated to the other side:
	// https://datatracker.ietf.org/doc/html/rfc4254#section-6.10
	//       byte      SSH_MSG_CHANNEL_REQUEST
	//       uint32    recipient channel
	//       string    "exit-status"
	//       boolean   FALSE
	//       uint32    exit_status
	// as well as SSH_MSG_CHANNEL_EOF (from CloseWrite())
	// So we can fully close the channel now
	if err := c.Dst.Close(); err != nil && !errors.Is(err, io.EOF) {
		c.logger.Error("Close failed", zap.Error(err))
	}

	c.logger.Debug("Channel fully closed")
}

type BidirectionalCopier struct {
	logger         *zap.Logger
	SourceToTarget ChannelCopyPair
	TargetToSource ChannelCopyPair
}

func (c *BidirectionalCopier) start() {
	var wg sync.WaitGroup

	// Either direction panicking closes both channel ends, so a dead copy direction cannot
	// leave the other blocked.
	wg.Go(func() {
		defer closeOnPanic(c.logger, c.close)

		c.SourceToTarget.copy()
	})
	wg.Go(func() {
		defer closeOnPanic(c.logger, c.close)

		c.TargetToSource.copy()
	})

	// Wait for both directions to finish
	wg.Wait()
}

func (c *BidirectionalCopier) close() {
	_ = c.SourceToTarget.Src.Close()
	_ = c.SourceToTarget.Dst.Close()
}
