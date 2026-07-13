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

// Factory for creating SSH Client and Server Connections (downstream and upstream).
type sshConnFactory interface {
	NewServerConn(c net.Conn, config *ssh.ServerConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error)
	NewClientConn(c net.Conn, addr string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error)
}

// NetDialer creates network connections.
type netDialerFactory interface {
	DialTimeout(network, address string, timeout time.Duration) (net.Conn, error)
}

// DefaultSSHConnFactory implements SSHConnFactory using the standard ssh package.
type defaultSSHConnFactory struct{}

//revive:disable-next-line:function-result-limit
//nolint:ireturn
func (f *defaultSSHConnFactory) NewServerConn(c net.Conn, config *ssh.ServerConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	return ssh.NewServerConn(c, config)
}

//revive:disable-next-line:function-result-limit
//nolint:ireturn
func (f *defaultSSHConnFactory) NewClientConn(c net.Conn, addr string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	return ssh.NewClientConn(c, addr, config)
}

// DefaultNetDialer implements NetDialer using the standard net package.
type defaultNetDialer struct{}

func (d *defaultNetDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}

// ConnPairFactory creates an SSH connection pair (downstream and upstream).
type connPairFactory interface {
	NewConnPair(logger *zap.Logger, sshCtx *sshContext,
		downstreamConn ssh.Conn, downstreamChannels <-chan ssh.NewChannel, downstreamRequests <-chan *ssh.Request,
		upstreamConn ssh.Conn, upstreamChannels <-chan ssh.NewChannel, upstreamRequests <-chan *ssh.Request) ConnPair
}

// DefaultConnPairFactory implements connPairFactory using SSHConnPair.
type defaultConnPairFactory struct{}

//nolint:ireturn
func (f *defaultConnPairFactory) NewConnPair(logger *zap.Logger, sshCtx *sshContext,
	downstreamConn ssh.Conn, downstreamChannels <-chan ssh.NewChannel, downstreamRequests <-chan *ssh.Request,
	upstreamConn ssh.Conn, upstreamChannels <-chan ssh.NewChannel, upstreamRequests <-chan *ssh.Request,
) ConnPair {
	return NewSSHConnPair(logger, sshCtx, downstreamConn, downstreamChannels, downstreamRequests, upstreamConn, upstreamChannels, upstreamRequests)
}

var errShuttingDown = errors.New("shutting down")

// Timeout for connecting to the upstream SSH server.
const upstreamConnTimeout = 10 * time.Second

type SSHProxy struct {
	mu sync.Mutex

	// Map of all active SSH connections
	connsMap map[ConnPair]struct{}

	// Wait group for active SSH connections
	wg sync.WaitGroup

	// Configuration for the proxy
	config           Config
	downstreamConfig *ssh.ServerConfig

	// Whether the proxy is shutting down
	shuttingDown bool

	// Dependencies for creating connections (injectable for testing)
	sshConnFactory  sshConnFactory
	netDialer       netDialerFactory
	connPairFactory connPairFactory
}

func NewProxy(config Config) *SSHProxy {
	return &SSHProxy{
		connsMap:        map[ConnPair]struct{}{},
		config:          config,
		sshConnFactory:  &defaultSSHConnFactory{},
		netDialer:       &defaultNetDialer{},
		connPairFactory: &defaultConnPairFactory{},
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

		// No longer serving
		if conn == nil {
			break
		}

		// Serve SSH connection in a separate goroutine
		go func() {
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
	downstreamSSHConn, downstreamSSHChannelsChan, downstreamSSHRequestsChan, err := p.sshConnFactory.NewServerConn(conn, p.downstreamConfig)
	if err != nil {
		logger.Error("Handshake failed", zap.Error(err))

		_ = conn.Close()

		return err
	}

	sshCtx := &sshContext{
		id:            hex.EncodeToString(downstreamSSHConn.SessionID()),
		username:      upstream.username,
		clientVersion: string(downstreamSSHConn.ClientVersion()),
	}

	upstreamConfig, err := p.config.GetUpstreamConfig(ctx, upstream)
	if err != nil {
		closeDownstreamSSH(downstreamSSHConn, downstreamSSHChannelsChan, logger, sshCtx)

		return err
	}

	// Start connection to upstream SSH server
	upstreamConn, err := p.netDialer.DialTimeout("tcp", upstream.address, upstreamConnTimeout)
	if err != nil {
		logger.Error("Failed to connect to upstream SSH server", zap.Error(err))

		closeDownstreamSSH(downstreamSSHConn, downstreamSSHChannelsChan, logger, sshCtx)

		return err
	}

	// Open the SSH connection to the upstream server
	upstreamSSHConn, upstreamSSHChannelsChan, upstreamSSHRequestsChan, err := p.sshConnFactory.NewClientConn(upstreamConn, upstream.address, upstreamConfig)
	if err != nil {
		logger.Error("Failed to connect to upstream SSH server", zap.Error(err))

		closeDownstreamSSH(downstreamSSHConn, downstreamSSHChannelsChan, logger, sshCtx)

		_ = upstreamConn.Close()

		return err
	}

	sshCtx.serverVersion = string(upstreamSSHConn.ServerVersion())

	logger.Info("SSH connection established", zap.Any("ssh", sshCtx.baseFields()))

	sshConnPair := p.connPairFactory.NewConnPair(logger, sshCtx,
		downstreamSSHConn, downstreamSSHChannelsChan, downstreamSSHRequestsChan,
		upstreamSSHConn, upstreamSSHChannelsChan, upstreamSSHRequestsChan)

	// Serve the SSH connection pair
	p.wg.Add(1)

	// Add the open SSH connection pair to the map
	p.mu.Lock()
	p.connsMap[sshConnPair] = struct{}{}
	p.mu.Unlock()

	sshConnPair.serve()

	logger.Info("SSH connection closed", zap.Any("ssh", sshCtx.withConnectionClose(sshConnPair.ChannelsOpened())))

	// Remove the closed SSH connection pair from the map
	p.mu.Lock()
	delete(p.connsMap, sshConnPair)
	p.mu.Unlock()

	p.wg.Done()

	return nil
}

// closeDownstreamSSH closes the connection and rejects any queued channels.
func closeDownstreamSSH(conn ssh.Conn, channels <-chan ssh.NewChannel, logger *zap.Logger, sshCtx *sshContext) {
	_ = conn.Close()

	for newChannel := range channels {
		chCtx := newSSHChannelContext(sshCtx, newChannel.ChannelType(), labelDownstream, labelUpstream)
		chLogger := logger.With(zap.Any("ssh", chCtx.baseFields()))
		chLogger.Debug("Rejecting channel")

		if err := newChannel.Reject(ssh.ConnectionFailed, "upstream connection failed"); err != nil {
			chLogger.Error("Failed to reject channel", zap.Error(err))
		}
	}
}
