// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

const defaultTimeout = 10 * time.Second

// sslAccepted answers an SSLRequest when the database agrees to start TLS.
const sslAccepted = 'S'

var (
	errEmptyPassword             = errors.New("empty password")
	errFailedToConnectUpstream   = errors.New("failed to connect to upstream")
	errFailedToTakeOverUpstream  = errors.New("failed to take over the upstream connection")
	errTLSRejected               = errors.New("TLS rejected")
	errFailedToSendCancelRequest = errors.New("failed to send cancel request")
)

// upstream is the database that a client connection is proxied to.
type upstream struct {
	// address is the database's host:port
	address string
	// tlsConfig is nil when the GAT's upstream TLS mode is plaintext.
	tlsConfig *tls.Config
}

// newUpstream sets the TLS ServerName from address.
func newUpstream(address string, tlsConfig *tls.Config) upstream {
	if tlsConfig != nil {
		host, _, _ := net.SplitHostPort(address)
		tlsConfig.ServerName = host
	}

	return upstream{address: address, tlsConfig: tlsConfig}
}

// runtimeParams is the client's startup parameters without the user and database.
// The pgconn config sets its own user and database.
func runtimeParams(startup *pgproto3.StartupMessage) map[string]string {
	params := maps.Clone(startup.Parameters)
	maps.DeleteFunc(params, func(name, _ string) bool {
		return name == "user" || name == "database"
	})

	return params
}

// connect logs in to the database with cred and takes over the raw connection once the session is ready.
func (u upstream) connect(
	ctx context.Context, startup *pgproto3.StartupMessage, cred credential,
) (*pgconn.HijackedConn, error) {
	config, err := u.connectConfig(startup, cred)
	if err != nil {
		return nil, err
	}

	pgConn, err := pgconn.ConnectConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedToConnectUpstream, err)
	}

	// pgconn may still have reads buffered or in flight, SyncConn drains them before the raw
	// connection is handover.
	if err := pgConn.SyncConn(ctx); err != nil {
		_ = pgConn.Close(ctx)

		return nil, fmt.Errorf("%w: %w", errFailedToTakeOverUpstream, err)
	}

	hijackedConn, err := pgConn.Hijack()
	if err != nil {
		_ = pgConn.Close(ctx)

		return nil, fmt.Errorf("%w: %w", errFailedToTakeOverUpstream, err)
	}

	return hijackedConn, nil
}

// connectConfig is the pgconn config that logs in to the database with credential.
func (u upstream) connectConfig(startup *pgproto3.StartupMessage, cred credential) (*pgconn.Config, error) {
	// ParseConfig falls back to the gateway host's ~/.pgpass when the password is empty.
	if cred.password == "" {
		return nil, errEmptyPassword
	}

	// `sslmode=disable` prevents ParseConfig from building a TLS config and a plaintext fallback.
	// Set the TLS config explicitly below.
	connString := (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(cred.user, cred.password),
		Host:     u.address,
		RawQuery: "sslmode=disable",
	}).String()

	config, err := pgconn.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedToConnectUpstream, err)
	}

	// The database stays out of the URL, since parsing the URL path drops a leading slash from the name.
	config.Database = startup.Parameters["database"]
	if config.Database == "" {
		config.Database = cred.user
	}

	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = defaultTimeout
	}

	config.TLSConfig = u.tlsConfig.Clone()
	if config.TLSConfig != nil && cred.certificate != nil {
		config.TLSConfig.Certificates = []tls.Certificate{*cred.certificate}
	}

	config.RuntimeParams = runtimeParams(startup)
	// ParseConfig also reads the PG* environment variables. Pin these values, since letting an environment variable
	// change them can lead to behavior we do not support.
	config.SSLNegotiation = "postgres"
	config.MinProtocolVersion = "3.0"
	config.MaxProtocolVersion = "3.0"
	config.RequireAuth = cred.requireAuth

	return config, nil
}

// forwardCancelRequest sends the CancelRequest on a connection of its own. A cancel carries no
// credential, so the TLS handshake presents no client certificate.
func (u upstream) forwardCancelRequest(ctx context.Context, cancel *pgproto3.CancelRequest) error {
	dialer := net.Dialer{Timeout: defaultTimeout}

	upstreamConn, err := dialer.DialContext(ctx, "tcp", u.address)
	if err != nil {
		return fmt.Errorf("%w: %w", errFailedToConnectUpstream, err)
	}

	defer func() { _ = upstreamConn.Close() }()

	// Shutdown cancels ctx. Closing the TCP connection then ends the wait for the database. The
	// callback runs on another goroutine, so it must not read upstreamConn, which TLS replaces.
	tcpConn := upstreamConn

	stop := context.AfterFunc(ctx, func() { _ = tcpConn.Close() })
	defer stop()

	_ = upstreamConn.SetDeadline(time.Now().Add(defaultTimeout))

	if u.tlsConfig != nil {
		tlsConn, err := startTLS(upstreamConn, u.tlsConfig)
		if err != nil {
			return fmt.Errorf("%w: %w", errFailedToConnectUpstream, err)
		}

		upstreamConn = tlsConn
	}

	client := pgproto3.NewFrontend(upstreamConn, upstreamConn)
	client.Send(cancel)

	if err := client.Flush(); err != nil {
		return fmt.Errorf("%w: %w", errFailedToSendCancelRequest, err)
	}

	// The database answers a cancel request with nothing but a close, so reading until EOF proves
	// it received the request before this side closes.
	if _, err := upstreamConn.Read(make([]byte, 1)); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: %w", errFailedToSendCancelRequest, err)
	}

	return nil
}

// startTLS asks the database to start TLS with an SSLRequest and runs the handshake when it agrees.
func startTLS(conn net.Conn, tlsConfig *tls.Config) (net.Conn, error) {
	client := pgproto3.NewFrontend(conn, conn)
	client.Send(&pgproto3.SSLRequest{})

	if err := client.Flush(); err != nil {
		return nil, err
	}

	var answer [1]byte

	if _, err := io.ReadFull(conn, answer[:]); err != nil {
		return nil, err
	}

	if answer[0] != sslAccepted {
		return nil, fmt.Errorf("%w: %q", errTLSRejected, answer[0])
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn, nil
}
