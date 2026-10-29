// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"errors"
	"net"
	"sync"

	"go.uber.org/zap"

	backendtls "gateway/internal/backend/tls"
	"gateway/internal/frontend"
)

var errShuttingDown = errors.New("shutting down")

type Proxy struct {
	mu sync.Mutex

	// Map of all active PostgreSQL connections
	conns map[frontend.Conn]struct{}

	// Wait group for active PostgreSQL connections
	wg sync.WaitGroup

	config Config

	shuttingDown bool
}

func NewProxy(config Config) *Proxy {
	return &Proxy{
		conns:  make(map[frontend.Conn]struct{}),
		config: config,
	}
}

func (p *Proxy) Start(ctx context.Context, listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				p.config.logger.System.Error("Failed to accept incoming connection", zap.Error(err))
			}

			break
		}

		go func() {
			defer closeOnPanic(p.config.logger.System, func() { _ = conn.Close() })

			err := p.serveConn(ctx, conn.(frontend.Conn))
			if err != nil {
				p.config.logger.System.Error("Failed to serve PostgreSQL connection", zap.Error(err))
			}
		}()
	}

	return nil
}

func (p *Proxy) Shutdown(_ context.Context) {
	p.mu.Lock()

	p.shuttingDown = true

	for conn := range p.conns {
		_ = conn.Close()
	}

	p.mu.Unlock()

	p.wg.Wait()
}

func (p *Proxy) serveConn(ctx context.Context, conn frontend.Conn) error {
	p.mu.Lock()

	if p.shuttingDown {
		p.mu.Unlock()

		_ = conn.Close()

		return errShuttingDown
	}

	p.wg.Add(1)
	defer p.wg.Done()

	p.conns[conn] = struct{}{}

	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		delete(p.conns, conn)
		p.mu.Unlock()
	}()

	logger := p.config.logger
	logger.Audit = logger.Audit.With(
		zap.Object("user", conn.GATClaims().User),
		zap.String("conn_id", conn.GetID()),
	)

	downstream := newDownstreamConn(conn)

	startup, cancel, err := downstream.handleStartupMessage()
	if err != nil {
		logger.System.Error("Failed to receive startup request", zap.Error(err))

		return downstream.reject(err)
	}

	tlsMode := conn.GATClaims().Resource.GatewayMetadata.Upstream.TLSMode
	upstream := newUpstream(conn.GetUpstreamAddress(), backendtls.NewUpstreamTLSConfig(tlsMode, p.config.caPool))

	if cancel != nil {
		err := upstream.forwardCancelRequest(ctx, cancel)
		if err != nil {
			logger.System.Error("Failed to forward the cancel request", zap.Error(err))
			logger.Audit.Error("pg cancel", zap.Uint32("process_id", cancel.ProcessID), zap.Error(err))
		} else {
			logger.Audit.Info("pg cancel", zap.Uint32("process_id", cancel.ProcessID))
		}

		_ = conn.Close()

		return err
	}

	if err := downstream.negotiateProtocolVersion(startup); err != nil {
		logger.System.Error("Failed to negotiate the protocol version", zap.Error(err))

		return downstream.reject(err)
	}

	auth := conn.GATClaims().Resource.GatewayMetadata.Auths[0]

	provider, err := newCredentialProvider(auth, p.config.passwords)
	if err != nil {
		logger.System.Error("Failed to get the database credential", zap.Error(err))

		return downstream.reject(errFailedToGetCredential)
	}

	cred, err := provider.retrieve(ctx)
	if err != nil {
		logger.System.Error("Failed to get the database credential", zap.Error(err))

		return downstream.reject(errFailedToGetCredential)
	}

	db, err := upstream.connect(ctx, startup, cred)
	if err != nil {
		logger.System.Error("Failed to connect to the database", zap.Error(err))

		return downstream.reject(err)
	}

	defer func() { _ = db.Conn.Close() }()

	if err := downstream.completeLogin(db); err != nil {
		logger.System.Error("Failed to accept the PostgreSQL client", zap.Error(err))

		return downstream.reject(err)
	}

	logger.System.Info("PostgreSQL connection established")

	logger.Audit = logger.Audit.With(
		zap.String("database_host", db.Config.Host),
		zap.String("database_user", db.Config.User),
		zap.String("database", db.Config.Database),
	)

	session := newRelay(logger, downstream, db, []observer{newAuditObserver(logger.Audit)})

	err = session.serve(ctx)

	logger.System.Info("PostgreSQL connection closed")

	return err
}

func closeOnPanic(logger *zap.Logger, closeFn func()) {
	recovered := recover() //nolint:revive // closeOnPanic itself is the deferred function
	if recovered == nil {
		return
	}

	logger.Error("Recovered from panic", zap.Any("panic", recovered), zap.Stack("stacktrace"))

	defer func() {
		if r := recover(); r != nil {
			logger.Error("Recovered from panic during cleanup", zap.Any("panic", r), zap.Stack("stacktrace"))
		}
	}()

	closeFn()
}
