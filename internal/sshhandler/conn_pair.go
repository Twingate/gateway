// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	labelDownstream = "downstream"
	labelUpstream   = "upstream"
)

// Denylists for channel types per direction (RFC 4254).
var (
	// disallowedDownstreamChannelTypes are channel types not allowed from downstream client.
	disallowedDownstreamChannelTypes = map[string]bool{
		"x11":             true, // server→client per RFC 4254 §6.3.2
		"forwarded-tcpip": true, // server→client per RFC 4254 §7.2
	}

	// disallowedUpstreamChannelTypes are channel types not allowed from upstream server.
	disallowedUpstreamChannelTypes = map[string]bool{
		"session":      true, // client→server per RFC 4254 §6.1
		"direct-tcpip": true, // client→server per RFC 4254 §7.2
		"x11":          true, // not supported by gateway
	}
)

// Denylists for global request types per direction (RFC 4254).
var (
	// disallowedUpstreamGlobalRequests are global request types not allowed from upstream server.
	disallowedUpstreamGlobalRequests = map[string]bool{
		"tcpip-forward":        true, // client→server per RFC 4254 §7.1
		"cancel-tcpip-forward": true, // client→server per RFC 4254 §7.1
	}
)

// sshConn is one side's handle on an SSH connection: the raw ssh.Conn plus its incoming channel
// and global-request streams (the trio ssh.NewServerConn/ssh.NewClientConn return together).
type sshConn struct {
	conn        ssh.Conn
	newChannels <-chan ssh.NewChannel
	requests    <-chan *ssh.Request
}

type SSHConnPair struct {
	logger *zap.Logger
	sshCtx *sshContext

	downstream sshConn
	upstream   sshConn

	// Counter for opened channels
	channelCount atomic.Int32

	// Wait group for all channel pairs to be finished
	wg sync.WaitGroup
}

func NewSSHConnPair(logger *zap.Logger, sshCtx *sshContext, downstream, upstream sshConn) *SSHConnPair {
	return &SSHConnPair{
		logger:     logger,
		sshCtx:     sshCtx,
		downstream: downstream,
		upstream:   upstream,
	}
}

func (c *SSHConnPair) ChannelsOpened() int {
	return int(c.channelCount.Load())
}

func (c *SSHConnPair) serve() {
	// When either side closes, close the other to unblock all ranging goroutines.
	c.wg.Go(func() {
		_ = c.downstream.conn.Wait()

		if err := c.upstream.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.logger.Debug("Failed to close upstream connection", zap.Error(err))
		}
	})

	c.wg.Go(func() {
		_ = c.upstream.conn.Wait()

		if err := c.downstream.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.logger.Debug("Failed to close downstream connection", zap.Error(err))
		}
	})

	// Forward global requests in both directions
	c.wg.Go(func() {
		c.forwardGlobalRequests(c.downstream.requests, c.upstream.conn, nil, labelDownstream, labelUpstream)
	})

	c.wg.Go(func() {
		c.forwardGlobalRequests(c.upstream.requests, c.downstream.conn, disallowedUpstreamGlobalRequests, labelUpstream, labelDownstream)
	})

	// Forward channels in both directions
	c.wg.Go(func() {
		c.forwardChannels(c.downstream.newChannels, c.upstream.conn, disallowedDownstreamChannelTypes, labelDownstream, labelUpstream)
	})

	c.wg.Go(func() {
		c.forwardChannels(c.upstream.newChannels, c.downstream.conn, disallowedUpstreamChannelTypes, labelUpstream, labelDownstream)
	})

	c.wg.Wait()
}

func (c *SSHConnPair) forwardChannels(channels <-chan ssh.NewChannel, targetConn ssh.Conn, disallowedTypes map[string]bool, source, target string) {
	for newChannel := range channels {
		channelType := newChannel.ChannelType()
		sshChannelCtx := newSSHChannelContext(c.sshCtx, channelType, source, target)
		logger := c.logger.With(zap.Any("ssh", sshChannelCtx.baseFields()))

		if disallowedTypes[channelType] {
			logger.Warn("SSH channel rejected")

			if err := newChannel.Reject(ssh.Prohibited, "channel type not allowed"); err != nil {
				logger.Error("Failed to reject channel", zap.Error(err))
			}

			continue
		}

		targetChannel, targetRequests, err := targetConn.OpenChannel(channelType, newChannel.ExtraData())
		if err != nil {
			logger.Error("Failed to open target channel", zap.Error(err))

			if err := newChannel.Reject(ssh.ConnectionFailed, "failed to open target channel"); err != nil {
				logger.Error("Failed to reject source channel", zap.Error(err))
			}

			continue
		}

		sourceChannel, sourceRequests, err := newChannel.Accept()
		if err != nil {
			logger.Error("Failed to accept source channel", zap.Error(err))

			if err := targetChannel.Close(); err != nil {
				logger.Error("Failed to close target channel", zap.Error(err))
			}

			go ssh.DiscardRequests(targetRequests)

			continue
		}

		c.channelCount.Add(1)

		logger.Info("SSH channel opened")

		channelPair := NewSSHChannelPair(
			c.logger,
			sshChannelCtx,
			c.upstream.conn.User(),
			sourceChannel, sourceRequests,
			targetChannel, targetRequests,
		)

		c.wg.Go(func() {
			channelPair.serve()
			logger.Info("SSH channel closed")
		})
	}
}

func (c *SSHConnPair) forwardGlobalRequests(requests <-chan *ssh.Request, dst ssh.Conn, disallowedTypes map[string]bool, source, target string) {
	for req := range requests {
		logger := c.logger.With(zap.Any("ssh", c.sshCtx.withGlobalRequest(req.Type, source, target)))

		if disallowedTypes[req.Type] {
			logger.Warn("SSH global request rejected")
			replyToGlobalRequest(req, false, nil, logger)

			continue
		}

		logger.Info("SSH global request")

		ok, payload, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			logger.Error("Failed to forward global request", zap.Error(err))
			replyToGlobalRequest(req, false, nil, logger)

			continue
		}

		replyToGlobalRequest(req, ok, payload, logger)
	}
}

func (c *SSHConnPair) close() {
	if err := c.downstream.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		c.logger.Error("Failed to close downstream connection", zap.Error(err))
	}

	if err := c.upstream.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		c.logger.Error("Failed to close upstream connection", zap.Error(err))
	}
}

func replyToGlobalRequest(req *ssh.Request, ok bool, payload []byte, logger *zap.Logger) {
	if !req.WantReply {
		return
	}

	if err := req.Reply(ok, payload); err != nil {
		logger.Error("Failed to reply to global request", zap.Error(err))
	}
}
