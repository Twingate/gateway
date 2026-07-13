// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"gateway/internal/connect"
)

var errShuttingDown = errors.New("shutting down")

// Timeout for connecting to the upstream SSH server.
const upstreamConnTimeout = 10 * time.Second

type SSHProxy struct {
	mu sync.Mutex

	// Map of all active SSH connections
	connsMap map[*SSHConnPair]struct{}

	// Wait group for active SSH connections
	wg sync.WaitGroup

	// Configuration for the proxy
	config           Config
	downstreamConfig *ssh.ServerConfig

	// Whether the proxy is shutting down
	shuttingDown bool
}

func NewProxy(config Config) *SSHProxy {
	return &SSHProxy{
		connsMap: map[*SSHConnPair]struct{}{},
		config:   config,
	}
}

func (p *SSHProxy) Start(ctx context.Context, listener net.Listener) error {
	if err := p.config.caConfig.Start(ctx); err != nil {
		return err
	}

	downstreamConfig, err := p.config.GetDownstreamConfig(ctx)
	if err != nil {
		return err
	}

	p.downstreamConfig = downstreamConfig

	// Start handling incoming SSH connections
	for {
		// Block until a connection is accepted
		conn, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				p.config.logger.Error("Failed to accept incoming connection", zap.Error(err))
			}

			break
		}

		// Serve SSH connection in a separate goroutine
		go func() {
			defer closeOnPanic(p.config.logger, func() { _ = conn.Close() })

			err := p.serveConn(ctx, conn.(connect.Conn))
			if err != nil {
				p.config.logger.Error("Failed to serve SSH connection", zap.Error(err))
			}
		}()
	}

	return nil
}

func (p *SSHProxy) Shutdown(_ctx context.Context) {
	// Try to close all the connections to cleanup
	p.mu.Lock()

	p.shuttingDown = true
	for conn := range p.connsMap {
		conn.close()
	}

	p.mu.Unlock()

	// Wait for all the goroutines handling the SSH connections to finish
	p.wg.Wait()
}

func (p *SSHProxy) serveConn(ctx context.Context, conn connect.Conn) error {
	p.mu.Lock()

	if p.shuttingDown {
		p.mu.Unlock()
		// reject the connection and return error
		_ = conn.Close()

		return errShuttingDown
	}

	p.mu.Unlock()

	// Setup audit logger for this connection
	logger := p.config.logger.Named("audit").With(
		zap.Object("user", conn.GATClaims().User),
		zap.String("conn_id", conn.GetID()),
	)

	upstream := upstream{
		address:  conn.GetAddress(),
		username: p.config.gatewayUsername,
	}

	// Give the proxyconn.ProxyConn TCP connection to the SSH server to start the SSH handshake
	downstreamSSHConn, downstreamChannels, downstreamRequests, err := ssh.NewServerConn(conn, p.downstreamConfig)
	if err != nil {
		logger.Error("Handshake failed", zap.Error(err))

		_ = conn.Close()

		return err
	}

	downstreamConn := connection{conn: downstreamSSHConn, channels: downstreamChannels, requests: downstreamRequests}

	sshCtx := &sshContext{
		id:            hex.EncodeToString(downstreamSSHConn.SessionID()),
		username:      upstream.username,
		clientVersion: string(downstreamSSHConn.ClientVersion()),
	}

	upstreamConfig, err := p.config.GetUpstreamConfig(ctx, upstream)
	if err != nil {
		closeDownstreamSSH(downstreamConn, logger, sshCtx)

		return err
	}

	// Start connection to upstream SSH server
	upstreamNetConn, err := net.DialTimeout("tcp", upstream.address, upstreamConnTimeout)
	if err != nil {
		logger.Error("Failed to connect to upstream SSH server", zap.Error(err))

		closeDownstreamSSH(downstreamConn, logger, sshCtx)

		return err
	}

	// Open the SSH connection to the upstream server
	upstreamSSHConn, upstreamChannels, upstreamRequests, err := ssh.NewClientConn(upstreamNetConn, upstream.address, upstreamConfig)
	if err != nil {
		logger.Error("Failed to connect to upstream SSH server", zap.Error(err))

		closeDownstreamSSH(downstreamConn, logger, sshCtx)

		_ = upstreamNetConn.Close()

		return err
	}

	upstreamConn := connection{conn: upstreamSSHConn, channels: upstreamChannels, requests: upstreamRequests}

	sshCtx.serverVersion = string(upstreamSSHConn.ServerVersion())

	logger.Info("SSH connection established", zap.Any("ssh", sshCtx.baseFields()))

	sshConnPair := NewSSHConnPair(logger, sshCtx, downstreamConn, upstreamConn)

	// Serve the SSH connection pair
	p.wg.Add(1)
	defer p.wg.Done()

	p.mu.Lock()
	p.connsMap[sshConnPair] = struct{}{}
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		delete(p.connsMap, sshConnPair)
		p.mu.Unlock()
	}()

	sshConnPair.serve()

	logger.Info("SSH connection closed", zap.Any("ssh", sshCtx.withConnectionClose(sshConnPair.ChannelsOpened())))

	return nil
}

func closeOnPanic(logger *zap.Logger, closeFn func()) {
	if recovered := recover(); recovered != nil { //nolint:revive // closeOnPanic itself is the deferred function
		logger.Error("Recovered from panic", zap.Any("panic", recovered), zap.Stack("stacktrace"))
		closeFn()
	}
}

// closeDownstreamSSH closes the connection and rejects any queued channels.
func closeDownstreamSSH(downstream connection, logger *zap.Logger, sshCtx *sshContext) {
	_ = downstream.conn.Close()

	for newChannel := range downstream.channels {
		chCtx := newSSHChannelContext(sshCtx, newChannel.ChannelType(), labelDownstream, labelUpstream)
		chLogger := logger.With(zap.Any("ssh", chCtx.baseFields()))
		chLogger.Debug("Rejecting channel")

		if err := newChannel.Reject(ssh.ConnectionFailed, "upstream connection failed"); err != nil {
			chLogger.Error("Failed to reject channel", zap.Error(err))
		}
	}
}
