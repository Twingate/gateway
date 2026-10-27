// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	backendtls "gateway/internal/backend/tls"
	"gateway/internal/frontend"
	"gateway/internal/token"
)

const defaultTimeout = 10 * time.Second

// sslAccepted answers an SSLRequest when the database agrees to start TLS.
const sslAccepted = 'S'

var (
	errUnsupportedAuthType       = errors.New("unsupported auth type")
	errEmptyPassword             = errors.New("empty password")
	errFailedToConnectUpstream   = errors.New("failed to connect to upstream")
	errFailedToTakeOverUpstream  = errors.New("failed to take over the upstream connection")
	errTLSRejected               = errors.New("TLS rejected")
	errFailedToSendCancelRequest = errors.New("failed to send cancel request")
)

type upstreamConfig struct {
	// address is the database's host:port
	address  string
	user     string
	password string
	database string
	// runtimeParams are the client's other startup parameters, carried over to the database
	runtimeParams map[string]string
	authType      token.AuthType
	tlsConfig     *tls.Config
}

func newUpstreamConfig(
	conn frontend.Conn, startup *pgproto3.StartupMessage, auth token.Auth, cred credential, caPool *x509.CertPool,
) upstreamConfig {
	database := startup.Parameters["database"]
	if database == "" {
		database = auth.User
	}

	return upstreamConfig{
		address:       conn.GetUpstreamAddress(),
		authType:      auth.Type,
		user:          auth.User,
		password:      cred.password,
		database:      database,
		runtimeParams: runtimeParams(startup),
		tlsConfig:     newUpstreamTLSConfig(conn, cred.certificate, caPool),
	}
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

// newUpstreamTLSConfig is the TLS client config based on the GAT's upstream TLS mode.
func newUpstreamTLSConfig(conn frontend.Conn, certificate *tls.Certificate, caPool *x509.CertPool) *tls.Config {
	tlsConfig := backendtls.NewUpstreamTLSConfig(conn.GATClaims().Resource.GatewayMetadata.Upstream.TLSMode, caPool)
	if tlsConfig == nil {
		return nil
	}

	host, _, _ := net.SplitHostPort(conn.GetUpstreamAddress())
	tlsConfig.ServerName = host

	if certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*certificate}
	}

	return tlsConfig
}

// connectUpstream authenticates to the upstream database and takes over the raw connection once
// the session is ready.
func connectUpstream(ctx context.Context, cfg upstreamConfig) (*pgconn.HijackedConn, error) {
	config, err := newConnectConfig(cfg)
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

	upstream, err := pgConn.Hijack()
	if err != nil {
		_ = pgConn.Close(ctx)

		return nil, fmt.Errorf("%w: %w", errFailedToTakeOverUpstream, err)
	}

	return upstream, nil
}

// newConnectConfig is the pgconn config that authenticates to the upstream database.
func newConnectConfig(cfg upstreamConfig) (*pgconn.Config, error) {
	// ParseConfig falls back to the gateway host's ~/.pgpass when the password is empty.
	if cfg.password == "" {
		return nil, errEmptyPassword
	}

	// `sslmode=disable` prevents ParseConfig from building a TLS config and a plaintext fallback.
	// Set the TLS config explicitly below.
	connString := (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(cfg.user, cfg.password),
		Host:     cfg.address,
		RawQuery: "sslmode=disable",
	}).String()

	config, err := pgconn.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedToConnectUpstream, err)
	}

	// The database stays out of the URL, since parsing the URL path drops a leading slash from the name.
	config.Database = cfg.database
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = defaultTimeout
	}

	config.TLSConfig = cfg.tlsConfig
	config.RuntimeParams = cfg.runtimeParams
	// ParseConfig also reads the PG* environment variables. Pin these values, since letting an environment variable
	// change them can lead to behavior we do not support.
	config.SSLNegotiation = "postgres"
	config.MinProtocolVersion = "3.0"
	config.MaxProtocolVersion = "3.0"

	switch cfg.authType {
	case token.AuthTypePassword:
		config.RequireAuth = "scram-sha-256"
	case token.AuthTypeAWSIAM, token.AuthTypeGCPIAM:
		config.RequireAuth = "password"
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedAuthType, cfg.authType)
	}

	return config, nil
}

// cancelUpstream forwards the client's CancelRequest to the database on a connection of its own,
// over TLS when the upstream TLS mode asks for it.
func cancelUpstream(conn frontend.Conn, cancel *pgproto3.CancelRequest, caPool *x509.CertPool) error {
	upstreamConn, err := net.DialTimeout("tcp", conn.GetUpstreamAddress(), defaultTimeout)
	if err != nil {
		return fmt.Errorf("%w: %w", errFailedToConnectUpstream, err)
	}

	defer func() { _ = upstreamConn.Close() }()

	_ = upstreamConn.SetDeadline(time.Now().Add(defaultTimeout))

	// A cancel carries no credential. The TLS handshake succeeds without a client certificate.
	if tlsConfig := newUpstreamTLSConfig(conn, nil, caPool); tlsConfig != nil {
		tlsConn, err := startTLS(upstreamConn, tlsConfig)
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
