// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"errors"
	"maps"
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

// Channel types (RFC 4254).
const (
	channelTypeSession        = "session"
	channelTypeDirectTCPIP    = "direct-tcpip"
	channelTypeForwardedTCPIP = "forwarded-tcpip"
	channelTypeX11            = "x11"
)

// SSH direct-tcpip / forwarded-tcpip channel open payload
// see: https://datatracker.ietf.org/doc/html/rfc4254#section-7.2
type tcpipChannelOpen struct {
	DestAddr string
	DestPort uint32
	OrigAddr string
	OrigPort uint32
}

// Global request types (RFC 4254).
const (
	globalRequestTCPIPForward       = "tcpip-forward"
	globalRequestCancelTCPIPForward = "cancel-tcpip-forward"
)

// SSH tcpip-forward / cancel-tcpip-forward global request payload
// see: https://datatracker.ietf.org/doc/html/rfc4254#section-7.1
type tcpipForwardReq struct {
	BindAddr string
	BindPort uint32
}

// SSH tcpip-forward reply payload, sent only when the request asked for a dynamic port (bind
// port 0); carries the port the server actually allocated.
// see: https://datatracker.ietf.org/doc/html/rfc4254#section-7.1
type tcpipForwardReply struct {
	BoundPort uint32
}

// Denylists for channel types per direction.
var (
	// disallowedDownstreamChannelTypes are channel types not allowed from downstream client.
	disallowedDownstreamChannelTypes = map[string]bool{
		channelTypeX11:            true, // server→client per RFC 4254 §6.3.2
		channelTypeForwardedTCPIP: true, // server→client per RFC 4254 §7.2
	}

	// disallowedUpstreamChannelTypes are channel types not allowed from upstream server.
	disallowedUpstreamChannelTypes = map[string]bool{
		channelTypeSession:     true, // client→server per RFC 4254 §6.1
		channelTypeDirectTCPIP: true, // client→server per RFC 4254 §7.2
		channelTypeX11:         true, // not supported by gateway
	}
)

// Denylists for global request types per direction.
//
// The OpenSSH host-key advertisement/proof extension manages host keys between two directly
// connected SSH peers, so both of its request types are blocked in both directions rather than
// relayed across the proxy's two connections: forwarding it would leak the upstream's host keys
// and internal hostname to the client. See
// https://datatracker.ietf.org/doc/draft-miller-sshm-hostkey-update/.
var (
	// disallowedDownstreamGlobalRequests are global request types not allowed from downstream client.
	disallowedDownstreamGlobalRequests = map[string]bool{
		"hostkeys-00@openssh.com":       true, // not proxied across connections
		"hostkeys-prove-00@openssh.com": true, // not proxied across connections
	}

	// disallowedUpstreamGlobalRequests are global request types not allowed from upstream server.
	disallowedUpstreamGlobalRequests = map[string]bool{
		globalRequestTCPIPForward:       true, // client→server per RFC 4254 §7.1
		globalRequestCancelTCPIPForward: true, // client→server per RFC 4254 §7.1
		"hostkeys-00@openssh.com":       true, // not proxied across connections
		"hostkeys-prove-00@openssh.com": true, // not proxied across connections
	}
)

// connection is one side of an established SSH connection: the trio returned by
// ssh.NewClientConn or ssh.NewServerConn.
type connection struct {
	conn     ssh.Conn
	channels <-chan ssh.NewChannel
	requests <-chan *ssh.Request
}

type SSHConnPair struct {
	logger *zap.Logger
	sshCtx *sshContext

	downstream connection
	upstream   connection

	// Counter for opened channels
	channelCount atomic.Int32

	// Wait group for all channel pairs to be finished
	wg sync.WaitGroup
}

func NewSSHConnPair(logger *zap.Logger, sshCtx *sshContext, downstream, upstream connection) *SSHConnPair {
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
		defer closeOnPanic(c.logger, c.close)

		_ = c.downstream.conn.Wait()

		if err := c.upstream.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.logger.Debug("Failed to close upstream connection", zap.Error(err))
		}
	})

	c.wg.Go(func() {
		defer closeOnPanic(c.logger, c.close)

		_ = c.upstream.conn.Wait()

		if err := c.downstream.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.logger.Debug("Failed to close downstream connection", zap.Error(err))
		}
	})

	// Forward global requests in both directions
	c.wg.Go(func() {
		defer closeOnPanic(c.logger, c.close)

		c.forwardGlobalRequests(c.downstream.requests, c.upstream.conn, disallowedDownstreamGlobalRequests, labelDownstream, labelUpstream)
	})

	c.wg.Go(func() {
		defer closeOnPanic(c.logger, c.close)

		c.forwardGlobalRequests(c.upstream.requests, c.downstream.conn, disallowedUpstreamGlobalRequests, labelUpstream, labelDownstream)
	})

	// Forward channels in both directions
	c.wg.Go(func() {
		defer closeOnPanic(c.logger, c.close)

		c.forwardChannels(c.downstream.channels, c.upstream.conn, disallowedDownstreamChannelTypes, labelDownstream, labelUpstream)
	})

	c.wg.Go(func() {
		defer closeOnPanic(c.logger, c.close)

		c.forwardChannels(c.upstream.channels, c.downstream.conn, disallowedUpstreamChannelTypes, labelUpstream, labelDownstream)
	})

	c.wg.Wait()
}

func (c *SSHConnPair) forwardChannels(channels <-chan ssh.NewChannel, targetConn ssh.Conn, disallowedTypes map[string]bool, source, target string) {
	for newChannel := range channels {
		channelType := newChannel.ChannelType()

		extra, parseErr := channelOpenExtra(channelType, newChannel.ExtraData())
		sshChannelCtx := newSSHChannelContext(c.sshCtx, channelType, source, target, extra)
		logger := c.logger.With(zap.Any("ssh", sshChannelCtx.baseFields()))

		if parseErr != nil {
			logger.Error("Failed to parse channel open", zap.Error(parseErr))
		}

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
			channel{ch: sourceChannel, requests: sourceRequests},
			channel{ch: targetChannel, requests: targetRequests},
		)

		c.wg.Go(func() {
			// A panic closes both channel ends, so a dead serving goroutine cannot leave the
			// pair half-open.
			defer closeOnPanic(c.logger, channelPair.close)

			channelPair.serve()
			logger.Info("SSH channel closed")
		})
	}
}

func (c *SSHConnPair) forwardGlobalRequests(requests <-chan *ssh.Request, dst ssh.Conn, disallowedTypes map[string]bool, source, target string) {
	for req := range requests {
		c.forwardGlobalRequest(req, dst, disallowedTypes, source, target)
	}
}

func (c *SSHConnPair) forwardGlobalRequest(req *ssh.Request, dst ssh.Conn, disallowedTypes map[string]bool, source, target string) {
	extra, parseErr := globalRequestLogFields(req.Type, req.Payload)

	// logger derives the fields on each call so every log line carries the detail accumulated
	// in extra so far.
	logger := func() *zap.Logger {
		return c.logger.With(zap.Any("ssh", c.sshCtx.withGlobalRequest(req.Type, source, target, extra)))
	}

	var (
		accepted     bool
		replyPayload []byte
		err          error
	)

	// Reply exactly once, on every path; early returns leave the defaults, which reject the request.
	defer func() {
		if err := req.Reply(accepted, replyPayload); err != nil {
			logger().Error("Failed to reply to global request", zap.Error(err))
		}
	}()

	if parseErr != nil {
		logger().Error("Failed to parse global request", zap.Error(parseErr))
	}

	if disallowedTypes[req.Type] {
		logger().Warn("SSH global request rejected")

		return
	}

	accepted, replyPayload, err = dst.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		logger().Error("Failed to forward global request", zap.Error(err))

		return
	}

	// SendRequest's accepted result is meaningless when no reply was asked for.
	if req.WantReply {
		extra["accepted"] = accepted
	}

	if accepted {
		replyFields, err := globalRequestReplyLogFields(req.Type, replyPayload)
		if err != nil {
			logger().Error("Failed to parse global request reply", zap.Error(err))
		}

		maps.Copy(extra, replyFields)
	}

	logger().Info("SSH global request")
}

func (c *SSHConnPair) close() {
	if err := c.downstream.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		c.logger.Error("Failed to close downstream connection", zap.Error(err))
	}

	if err := c.upstream.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		c.logger.Error("Failed to close upstream connection", zap.Error(err))
	}
}

// channelOpenExtra returns the forwarding details parsed from a direct-tcpip or forwarded-tcpip
// channel open payload for audit logging; the map is empty for other channel types.
func channelOpenExtra(channelType string, payload []byte) (map[string]any, error) {
	switch channelType {
	case channelTypeDirectTCPIP, channelTypeForwardedTCPIP:
		var open tcpipChannelOpen
		if err := ssh.Unmarshal(payload, &open); err != nil {
			return nil, err
		}

		return map[string]any{
			"destination_address": open.DestAddr,
			"destination_port":    open.DestPort,
			"originator_address":  open.OrigAddr,
			"originator_port":     open.OrigPort,
		}, nil
	default:
		return map[string]any{}, nil
	}
}

// globalRequestLogFields returns the type-specific audit-log fields parsed from a global
// request payload; the map is empty for request types with no auditable detail. The map is
// non-nil even on a parse error, so the caller can keep accumulating detail into it.
func globalRequestLogFields(reqType string, payload []byte) (map[string]any, error) {
	switch reqType {
	case globalRequestTCPIPForward, globalRequestCancelTCPIPForward:
		var fwd tcpipForwardReq
		if err := ssh.Unmarshal(payload, &fwd); err != nil {
			return map[string]any{}, err
		}

		return map[string]any{
			"bind_address": fwd.BindAddr,
			"bind_port":    fwd.BindPort,
		}, nil
	default:
		return map[string]any{}, nil
	}
}

// globalRequestReplyLogFields returns the type-specific audit-log fields parsed from an accepted
// global request's reply payload; the map is empty for request types with no reply-derived detail.
func globalRequestReplyLogFields(reqType string, payload []byte) (map[string]any, error) {
	switch reqType {
	case globalRequestTCPIPForward:
		if len(payload) == 0 {
			return map[string]any{}, nil
		}

		var reply tcpipForwardReply
		if err := ssh.Unmarshal(payload, &reply); err != nil {
			return nil, err
		}

		return map[string]any{"allocated_port": reply.BoundPort}, nil
	default:
		return map[string]any{}, nil
	}
}
