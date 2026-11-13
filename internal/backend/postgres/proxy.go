// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"
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
		logger.System.Error("Failed to receive startup message", zap.Error(err))

		reason := "startup_failed"
		if errors.Is(err, errReplicationNotSupported) {
			reason = "replication_not_supported"
		}

		logger.Audit.Error("pg_connect_failed", zap.String("error", reason))
		downstream.reject(err)

		return err
	}

	tlsMode := conn.GATClaims().Resource.GatewayMetadata.Upstream.TLSMode
	upstream := newUpstream(conn.GetUpstreamAddress(), backendtls.NewUpstreamTLSConfig(tlsMode, p.config.caPool))

	if cancel != nil {
		err := upstream.forwardCancelRequest(ctx, cancel)
		if err != nil {
			logger.System.Error("Failed to forward the cancel request", zap.Error(err))

			reason := "cancel_failed"
			if errors.Is(err, errFailedToConnectUpstream) {
				reason = "unreachable_upstream"
			}

			logger.Audit.Error("pg_cancel", zap.Uint32("process_id", cancel.ProcessID), zap.String("error", reason))
		} else {
			logger.Audit.Info("pg_cancel", zap.Uint32("process_id", cancel.ProcessID))
		}

		_ = conn.Close()

		return err
	}

	if err := downstream.negotiateProtocolVersion(startup); err != nil {
		logger.System.Error("Failed to negotiate the protocol version", zap.Error(err))
		logger.Audit.Error("pg_connect_failed", zap.String("error", "startup_failed"))
		downstream.reject(err)

		return err
	}

	auth := conn.GATClaims().Resource.GatewayMetadata.Auths[0]

	provider, err := newCredentialProvider(auth, p.config.passwords)
	if err != nil {
		logger.System.Error("Failed to get the database credential", zap.Error(err))
		logger.Audit.Error("pg_connect_failed", zap.String("error", "credential_failed"))
		downstream.reject(errFailedToGetCredential)

		return errFailedToGetCredential
	}

	cred, err := provider.get(ctx)
	if err != nil {
		logger.System.Error("Failed to get the database credential", zap.Error(err))
		logger.Audit.Error("pg_connect_failed", zap.String("error", "credential_failed"))
		downstream.reject(errFailedToGetCredential)

		return errFailedToGetCredential
	}

	dbConn, err := upstream.connect(ctx, startup, cred)
	if err != nil {
		logger.System.Error("Failed to connect to the database", zap.Error(err))

		reason := "login_rejected"

		// A database error is relayed as is; anything else carries the upstream address and TLS detail.
		if _, ok := errors.AsType[*pgconn.PgError](err); !ok {
			err = errFailedToConnectUpstream
			reason = "unreachable_upstream"
		}

		logger.Audit.Error("pg_connect_failed", zap.String("error", reason))
		downstream.reject(err)

		return err
	}

	defer func() { _ = dbConn.Conn.Close() }()

	if err := downstream.completeLogin(dbConn); err != nil {
		logger.System.Error("Failed to accept the PostgreSQL client", zap.Error(err))
		logger.Audit.Error("pg_connect_failed", zap.String("error", "startup_failed"))
		downstream.reject(err)

		return err
	}

	logger.Audit = logger.Audit.With(
		zap.Dict("db",
			zap.String("user", dbConn.Config.User),
			zap.String("name", dbConn.Config.Database),
		),
		zap.Uint32("process_id", dbConn.PID),
	)

	logger.Audit.Info("pg_connect")

	relay := newRelay(logger.System, downstream, dbConn, newAuditObserver(logger.Audit))

	err = relay.serve(ctx)
	if err != nil {
		logger.Audit.Error("pg_disconnect", zap.String("error", "relay_failed"))
	} else {
		logger.Audit.Info("pg_disconnect")
	}

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
