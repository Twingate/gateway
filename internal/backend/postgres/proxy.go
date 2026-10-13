// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"go.uber.org/zap"

	"gateway/internal/frontend"
	"gateway/internal/token"
)

var (
	errShuttingDown       = errors.New("shutting down")
	errNoAuth             = errors.New("resource has no auths")
	errUnknownCredential  = errors.New("unknown credential")
	errUnsupportedAuth    = errors.New("unsupported auth type")
	errUnsupportedStartup = errors.New("unsupported startup message type")
)

const (
	upstreamDialTimeout = 10 * time.Second
	handshakeTimeout    = 30 * time.Second
)

// netDialerFactory creates outbound TCP connections. Injectable for tests.
type netDialerFactory interface {
	DialTimeout(network, address string, timeout time.Duration) (net.Conn, error)
}

type defaultNetDialer struct{}

func (defaultNetDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}

// Proxy is the PostgreSQL protocol proxy handler.
type Proxy struct {
	mu sync.Mutex

	// Active downstream/upstream socket pairs, closed on Shutdown so Serve goroutines unblock.
	connsMap map[*activeConn]struct{}

	wg sync.WaitGroup

	config       Config
	shuttingDown bool

	netDialer    netDialerFactory
	scramFactory scramClientFactory
}

type activeConn struct {
	downConn net.Conn
	upConn   net.Conn
}

func (a *activeConn) close() {
	if a.downConn != nil {
		_ = a.downConn.Close()
	}

	if a.upConn != nil {
		_ = a.upConn.Close()
	}
}

func NewProxy(cfg Config) *Proxy {
	return &Proxy{
		connsMap:     map[*activeConn]struct{}{},
		config:       cfg,
		netDialer:    defaultNetDialer{},
		scramFactory: defaultSCRAMClientFactory{},
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

		if conn == nil {
			break
		}

		go func() {
			if err := p.Serve(ctx, conn.(frontend.Conn)); err != nil {
				p.config.logger.System.Error("Failed to serve PostgreSQL connection", zap.Error(err))
			}
		}()
	}

	return nil
}

func (p *Proxy) Shutdown(_ context.Context) {
	p.mu.Lock()
	p.shuttingDown = true

	for ac := range p.connsMap {
		ac.close()
	}

	p.mu.Unlock()

	p.wg.Wait()
}

func (p *Proxy) Serve(ctx context.Context, conn frontend.Conn) error {
	p.mu.Lock()

	if p.shuttingDown {
		p.mu.Unlock()

		_ = conn.Close()

		return errShuttingDown
	}

	p.mu.Unlock()

	return p.serveConn(ctx, conn)
}

func (p *Proxy) serveConn(ctx context.Context, conn frontend.Conn) error {
	logger := p.config.logger.Audit.With(
		zap.Object("user", conn.GATClaims().User),
		zap.String("conn_id", conn.GetID()),
	)

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

	backend := pgproto3.NewBackend(conn, conn)

	startup, cancel, err := receiveStartupWithSSL(conn, backend)
	if err != nil {
		logger.Error("Startup handshake failed", zap.Error(err))
		sendErrorAndClose(conn, backend, "08P01", err.Error())

		return err
	}

	upstreamAddress := conn.GetUpstreamAddress()
	logger = logger.With(zap.String("upstream_address", upstreamAddress))

	if cancel != nil {
		return p.forwardCancel(logger, conn, upstreamAddress, cancel)
	}

	user, password, err := p.resolveAuth(conn.GATClaims().Resource.GatewayMetadata.Auths)
	if err != nil {
		logger.Error("Failed to resolve upstream authentication", zap.Error(err))
		sendErrorAndClose(conn, backend, "28000", "gateway cannot authenticate to the upstream for this resource")

		return err
	}

	database := startup.Parameters["database"]

	if database == "" {
		// PG defaults `database` to `user` when absent. We're about to overwrite
		// `user`, so lock in the client's intended database before doing so.
		database = startup.Parameters["user"]
	}

	startup.Parameters["database"] = database
	startup.Parameters["user"] = user

	logger = logger.With(
		zap.String("pg_user", user),
		zap.String("pg_database", database),
	)

	upConn, err := p.netDialer.DialTimeout("tcp", upstreamAddress, upstreamDialTimeout)
	if err != nil {
		logger.Error("Failed to connect to upstream PostgreSQL server", zap.Error(err))
		sendErrorAndClose(conn, backend, "08006", "unable to reach upstream")

		return err
	}

	ac := &activeConn{downConn: conn, upConn: upConn}

	p.mu.Lock()

	if p.shuttingDown {
		p.mu.Unlock()

		ac.close()

		return errShuttingDown
	}

	p.connsMap[ac] = struct{}{}
	p.wg.Add(1)
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		delete(p.connsMap, ac)
		p.mu.Unlock()
		p.wg.Done()

		ac.close()
	}()

	pgFrontend := pgproto3.NewFrontend(upConn, upConn)

	_ = upConn.SetDeadline(time.Now().Add(handshakeTimeout))

	pgFrontend.Send(startup)

	if err := pgFrontend.Flush(); err != nil {
		logger.Error("Failed to send startup to upstream", zap.Error(err))
		sendErrorAndClose(conn, backend, "08006", "upstream handshake failed")

		return fmt.Errorf("send upstream startup: %w", err)
	}

	if err := authenticateUpstream(pgFrontend, user, password, p.scramFactory); err != nil {
		logger.Error("Upstream authentication failed", zap.Error(err))
		sendErrorAndClose(conn, backend, "28P01", "upstream authentication failed")

		return err
	}

	// Upstream auth succeeded. Tell the client they're in.
	backend.Send(&pgproto3.AuthenticationOk{})

	if err := backend.Flush(); err != nil {
		logger.Error("Failed to send AuthenticationOk to client", zap.Error(err))

		return fmt.Errorf("send downstream authok: %w", err)
	}

	// Clear the handshake deadlines; steady-state relay has no deadline.
	_ = conn.SetDeadline(time.Time{})
	_ = upConn.SetDeadline(time.Time{})

	logger.Info("PostgreSQL connection established")

	err = relay(ctx, logger, conn, upConn, backend, pgFrontend)

	logger.Info("PostgreSQL connection closed", zap.Error(err))

	return err
}

// receiveStartupWithSSL handles a leading SSLRequest or GSSEncRequest (by responding 'N';
// TLS is already handled by the outer Twingate tunnel) and returns the StartupMessage or
// CancelRequest that follows. Exactly one of the two is non-nil when err is nil.
func receiveStartupWithSSL(conn net.Conn, backend *pgproto3.Backend) (*pgproto3.StartupMessage, *pgproto3.CancelRequest, error) {
	for {
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return nil, nil, fmt.Errorf("read startup: %w", err)
		}

		switch m := msg.(type) {
		case *pgproto3.StartupMessage:
			return m, nil, nil

		case *pgproto3.SSLRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, nil, fmt.Errorf("reject SSLRequest: %w", err)
			}
			// Fall through to read the real StartupMessage.

		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, nil, fmt.Errorf("reject GSSEncRequest: %w", err)
			}

		case *pgproto3.CancelRequest:
			return nil, m, nil

		default:
			return nil, nil, fmt.Errorf("%w: %T", errUnsupportedStartup, msg)
		}
	}
}

// forwardCancel relays a CancelRequest to the upstream at upstreamAddress. The request names
// the upstream backend by its own process ID and secret key, so it needs no upstream
// credential and no Gateway-side session lookup.
func (p *Proxy) forwardCancel(logger *zap.Logger, conn net.Conn, upstreamAddress string, cancel *pgproto3.CancelRequest) error {
	defer conn.Close()

	logger.Info("pg cancel", zap.Uint32("process_id", cancel.ProcessID))

	upConn, err := p.netDialer.DialTimeout("tcp", upstreamAddress, upstreamDialTimeout)
	if err != nil {
		logger.Error("Failed to connect to upstream PostgreSQL server for cancel", zap.Error(err))

		return fmt.Errorf("dial upstream for cancel: %w", err)
	}

	defer upConn.Close()

	_ = upConn.SetDeadline(time.Now().Add(handshakeTimeout))

	pgFrontend := pgproto3.NewFrontend(upConn, upConn)
	pgFrontend.Send(cancel)

	if err := pgFrontend.Flush(); err != nil {
		logger.Error("Failed to send cancel to upstream", zap.Error(err))

		return fmt.Errorf("send upstream cancel: %w", err)
	}

	// The upstream never replies to a CancelRequest; it closes the connection once it has
	// processed the request. Waiting for that keeps the client's cancel synchronous, as libpq's is.
	_, _ = io.Copy(io.Discard, upConn)

	return nil
}

// resolveAuth returns the database user and password to authenticate to the upstream with,
// from the first entry of auths. Only the password type is supported; its credential must
// name a credential in the Gateway config.
func (p *Proxy) resolveAuth(auths []token.Auth) (user, password string, err error) {
	if len(auths) == 0 {
		return "", "", errNoAuth
	}

	auth := auths[0]

	if auth.Type != token.AuthTypePassword {
		return "", "", fmt.Errorf("%w: %q", errUnsupportedAuth, auth.Type)
	}

	password, ok := p.config.passwordsByCredential[auth.Credential]
	if !ok {
		return "", "", fmt.Errorf("%w: %q", errUnknownCredential, auth.Credential)
	}

	return auth.User, password, nil
}

// sendErrorAndClose writes an ErrorResponse with the given SQLSTATE code and
// message, then closes the downstream connection. Best-effort — callers have
// already logged the underlying cause.
func sendErrorAndClose(conn net.Conn, backend *pgproto3.Backend, code, message string) {
	backend.Send(&pgproto3.ErrorResponse{
		Severity: "FATAL",
		Code:     code,
		Message:  message,
	})
	_ = backend.Flush()
	_ = conn.Close()
}
