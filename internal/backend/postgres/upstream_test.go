// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	backendtls "gateway/internal/backend/tls"
	gatewayconfig "gateway/internal/config"
	"gateway/internal/frontend"
	"gateway/internal/token"
)

const testDatabaseUser = "gateway"

var passwordAuth = token.Auth{
	Type:     token.AuthTypePassword,
	User:     testDatabaseUser,
	Password: &token.PasswordAuth{Credential: testCredential},
}

// newProxyConn wraps conn in the frontend.ProxyConn the proxy serves, with test GAT claims and
// the address of the upstream the proxy dials.
func newProxyConn(conn net.Conn, upstreamAddr string, tlsMode token.TLSClientMode, auth token.Auth) *frontend.ProxyConn {
	upstreamHost, port, _ := net.SplitHostPort(upstreamAddr)
	upstreamPort, _ := strconv.Atoi(port)

	proxyConn := frontend.NewProxyConn(conn, nil, nil, zap.NewNop(),
		frontend.CreateProxyConnMetrics(prometheus.NewRegistry()))
	proxyConn.Claims = &token.GATClaims{
		Resource: token.Resource{
			ID:      "resource-1",
			Address: upstreamHost,
			GatewayMetadata: token.GatewayMetadata{
				Upstream: token.Upstream{Port: upstreamPort, TLSMode: tlsMode},
				Auths:    token.Auths{auth},
			},
		},
	}
	proxyConn.UpstreamHost = upstreamHost
	proxyConn.ID = "test-conn-id"

	return proxyConn
}

func TestNewUpstreamConfig(t *testing.T) {
	tests := []struct {
		name         string
		tlsMode      token.TLSClientMode
		database     string
		wantDatabase string
		wantTLS      bool
	}{
		{name: "plaintext", tlsMode: token.TLSClientModeNone, database: "app", wantDatabase: "app"},
		{name: "TLS", tlsMode: token.TLSClientModeVerifyFull, database: "app", wantDatabase: "app", wantTLS: true},
		{name: "no database falls back to the GAT token's auth entry's user", tlsMode: token.TLSClientModeNone, wantDatabase: testDatabaseUser},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startup := &pgproto3.StartupMessage{
				ProtocolVersion: pgproto3.ProtocolVersion30,
				Parameters: map[string]string{
					"user":             "alice", // Dropped in favor of the GAT token's auth entry's user.
					"application_name": "psql",
				},
			}
			if tt.database != "" {
				startup.Parameters["database"] = tt.database
			}

			conn := newProxyConn(nil, "db.acme.int:5432", tt.tlsMode, passwordAuth)

			upstream := newUpstreamConfig(conn, startup, passwordAuth, credential{password: "secret"}, x509.NewCertPool())

			assert.Equal(t, "db.acme.int:5432", upstream.address)
			assert.Equal(t, token.AuthTypePassword, upstream.authType)
			assert.Equal(t, testDatabaseUser, upstream.user)
			assert.Equal(t, "secret", upstream.password)
			assert.Equal(t, tt.wantDatabase, upstream.database)
			assert.Equal(t, map[string]string{"application_name": "psql"}, upstream.runtimeParams)
			assert.Equal(t, tt.wantTLS, upstream.tlsConfig != nil)
		})
	}
}

func TestNewConnectConfig(t *testing.T) {
	// Don't allow overriding the upstream config with environment variables
	for name, value := range map[string]string{
		"PGHOST":               "env.acme.int",
		"PGPORT":               "5433",
		"PGUSER":               "env-user",
		"PGPASSWORD":           "env-secret",
		"PGDATABASE":           "env-db",
		"PGSSLNEGOTIATION":     "direct",
		"PGMINPROTOCOLVERSION": "3.2",
		"PGMAXPROTOCOLVERSION": "3.2",
		"PGREQUIREAUTH":        "md5",
	} {
		t.Setenv(name, value)
	}

	baseConfig := upstreamConfig{
		address:       "db.acme.int:5432",
		authType:      token.AuthTypePassword,
		user:          testDatabaseUser,
		password:      "secret",
		database:      "app",
		runtimeParams: map[string]string{"application_name": "psql"},
	}

	tests := []struct {
		name            string
		setupCfg        func(cfg *upstreamConfig)
		wantRequireAuth string
		wantErr         error
	}{
		{
			name:            "password in plaintext",
			setupCfg:        func(*upstreamConfig) {},
			wantRequireAuth: "scram-sha-256",
		},
		{
			name: "URL characters in the user, password and database",
			setupCfg: func(cfg *upstreamConfig) {
				cfg.user = "app@acme"
				cfg.password = "p@ss:w/rd?#%"
				cfg.database = "/app/db?x"
			},
			wantRequireAuth: "scram-sha-256",
		},
		{
			name: "IAM over TLS",
			setupCfg: func(cfg *upstreamConfig) {
				cfg.authType = token.AuthTypeAWSIAM
				cfg.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			},
			wantRequireAuth: "password",
		},
		{
			name:     "unsupported auth type",
			setupCfg: func(cfg *upstreamConfig) { cfg.authType = "kerberos" },
			wantErr:  errUnsupportedAuthType,
		},
		{
			name:     "empty password",
			setupCfg: func(cfg *upstreamConfig) { cfg.password = "" },
			wantErr:  errEmptyPassword,
		},
		{
			name:     "port out of range",
			setupCfg: func(cfg *upstreamConfig) { cfg.address = "db.acme.int:65536" },
			wantErr:  errFailedToConnectUpstream,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := baseConfig
			tt.setupCfg(&upstream)

			config, err := newConnectConfig(upstream)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)

			assert.Equal(t, upstream.user, config.User)
			assert.Equal(t, upstream.password, config.Password)
			assert.Equal(t, "db.acme.int", config.Host)
			assert.EqualValues(t, 5432, config.Port)
			assert.Equal(t, upstream.database, config.Database)
			assert.Empty(t, config.Fallbacks)
			assert.Same(t, upstream.tlsConfig, config.TLSConfig)
			assert.Equal(t, upstream.runtimeParams, config.RuntimeParams)
			assert.Equal(t, "postgres", config.SSLNegotiation)
			assert.Equal(t, "3.0", config.MinProtocolVersion)
			assert.Equal(t, "3.0", config.MaxProtocolVersion)
			assert.Equal(t, "prefer", config.ChannelBinding)
			assert.Equal(t, tt.wantRequireAuth, config.RequireAuth)
		})
	}
}

func TestNewConnectConfig_ConnectTimeout(t *testing.T) {
	tests := []struct {
		name              string
		connectTimeoutEnv string
		want              time.Duration
	}{
		{
			name: "default when unset",
			want: defaultTimeout,
		},
		{
			name:              "PGCONNECT_TIMEOUT overrides the default",
			connectTimeoutEnv: "30",
			want:              30 * time.Second,
		},
		{
			name:              "zero falls back to the default",
			connectTimeoutEnv: "0",
			want:              defaultTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PGCONNECT_TIMEOUT", tt.connectTimeoutEnv)

			config, err := newConnectConfig(upstreamConfig{
				address:  "db.acme.int:5432",
				authType: token.AuthTypePassword,
				user:     testDatabaseUser,
				password: "secret",
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, config.ConnectTimeout)
		})
	}
}

func TestNewUpstreamTLSConfig(t *testing.T) {
	certificate := &tls.Certificate{Certificate: [][]byte{{1}}}
	caPool := x509.NewCertPool()

	tests := []struct {
		name             string
		tlsMode          token.TLSClientMode
		certificate      *tls.Certificate
		wantCertificates []tls.Certificate
	}{
		{name: "plaintext", tlsMode: token.TLSClientModeNone},
		{name: "verified, no client certificate", tlsMode: token.TLSClientModeVerifyFull},
		{name: "verified, client certificate", tlsMode: token.TLSClientModeVerifyCA, certificate: certificate, wantCertificates: []tls.Certificate{*certificate}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig := newUpstreamTLSConfig(newProxyConn(nil, "db.acme.int:5432", tt.tlsMode, passwordAuth), tt.certificate, caPool)

			if tt.tlsMode == token.TLSClientModeNone {
				assert.Nil(t, tlsConfig)

				return
			}

			require.NotNil(t, tlsConfig)
			assert.Equal(t, "db.acme.int", tlsConfig.ServerName)
			assert.Equal(t, tt.wantCertificates, tlsConfig.Certificates)
		})
	}
}

// newUpstreamListener returns a loopback listener standing in for the database, and its address.
func newUpstreamListener(t *testing.T) (net.Listener, string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { _ = listener.Close() })

	return listener, listener.Addr().String()
}

// acceptUpstream accepts the connection the code under test dialed.
func acceptUpstream(t *testing.T, listener net.Listener) net.Conn {
	t.Helper()

	conn, err := listener.Accept()
	require.NoError(t, err)

	t.Cleanup(func() { _ = conn.Close() })

	return conn
}

// acceptTLS agrees to the SSLRequest and serves the test certificate.
func acceptTLS(t *testing.T, conn net.Conn) *tls.Conn {
	t.Helper()

	msg, err := pgproto3.NewBackend(conn, conn).ReceiveStartupMessage()
	require.NoError(t, err)
	require.IsType(t, &pgproto3.SSLRequest{}, msg)

	_, err = conn.Write([]byte{sslAccepted})
	require.NoError(t, err)

	certificate, err := tls.LoadX509KeyPair(testCertificateFile, testPrivateKeyFile)
	require.NoError(t, err)

	return tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
}

// refuseTLS answers the SSLRequest with N.
func refuseTLS(t *testing.T, conn net.Conn) {
	t.Helper()

	msg, err := pgproto3.NewBackend(conn, conn).ReceiveStartupMessage()
	require.NoError(t, err)
	require.IsType(t, &pgproto3.SSLRequest{}, msg)

	_, err = conn.Write([]byte{'N'})
	require.NoError(t, err)
}

// newTestCAPool trusts the test certificate.
func newTestCAPool(t *testing.T) *x509.CertPool {
	t.Helper()

	caPool, err := backendtls.NewCAPool([]gatewayconfig.UpstreamTrustedCABundle{{File: testCertificateFile}})
	require.NoError(t, err)

	return caPool
}

func TestConnectUpstream_Success(t *testing.T) {
	type result struct {
		upstream *pgconn.HijackedConn
		err      error
	}

	listener, address := newUpstreamListener(t)
	cfg := upstreamConfig{
		address:       address,
		authType:      token.AuthTypeAWSIAM,
		user:          testDatabaseUser,
		password:      "secret",
		database:      "app",
		runtimeParams: map[string]string{"application_name": "psql"},
		tlsConfig:     &tls.Config{RootCAs: newTestCAPool(t), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12},
	}

	done := make(chan result, 1)

	go func() {
		upstream, err := connectUpstream(t.Context(), cfg)
		done <- result{upstream: upstream, err: err}
	}()

	// The database agrees to TLS, then asks for a cleartext password and accepts it.
	conn := acceptUpstream(t, listener)
	tlsConn := acceptTLS(t, conn)
	backend := pgproto3.NewBackend(tlsConn, tlsConn)
	startup, err := backend.ReceiveStartupMessage()
	require.NoError(t, err)
	assert.Equal(t, &pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters:      map[string]string{"user": testDatabaseUser, "database": "app", "application_name": "psql"},
	}, startup)

	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	require.NoError(t, backend.Flush())

	msg, err := backend.Receive()
	require.NoError(t, err)
	assert.Equal(t, &pgproto3.PasswordMessage{Password: "secret"}, msg)

	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "17.0"})
	backend.Send(&pgproto3.BackendKeyData{ProcessID: 42, SecretKey: []byte{1, 2, 3, 4}})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	require.NoError(t, backend.Flush())

	res := <-done
	require.NoError(t, res.err)

	t.Cleanup(func() { _ = res.upstream.Conn.Close() })

	assert.EqualValues(t, 42, res.upstream.PID)
	assert.Equal(t, []byte{1, 2, 3, 4}, res.upstream.SecretKey)
	assert.Equal(t, map[string]string{"server_version": "17.0"}, res.upstream.ParameterStatuses)
	assert.EqualValues(t, 'I', res.upstream.TxStatus)
}

func TestConnectUpstream_Error(t *testing.T) {
	t.Run("upstream unreachable", func(t *testing.T) {
		listener, address := newUpstreamListener(t)
		require.NoError(t, listener.Close())

		cfg := upstreamConfig{address: address, authType: token.AuthTypePassword, user: testDatabaseUser, password: "secret"}

		_, err := connectUpstream(t.Context(), cfg)

		require.ErrorIs(t, err, errFailedToConnectUpstream)
	})

	t.Run("unsupported auth type", func(t *testing.T) {
		cfg := upstreamConfig{address: "db.acme.int:5432", authType: "kerberos", user: testDatabaseUser, password: "secret"}

		_, err := connectUpstream(t.Context(), cfg)

		require.ErrorIs(t, err, errUnsupportedAuthType)
	})
}

func TestCancelUpstream(t *testing.T) {
	cancel := &pgproto3.CancelRequest{ProcessID: 42, SecretKey: []byte{1, 2, 3, 4}}

	receiveCancel := func(t *testing.T, conn net.Conn) {
		t.Helper()

		msg, err := pgproto3.NewBackend(conn, conn).ReceiveStartupMessage()
		require.NoError(t, err)
		assert.Equal(t, cancel, msg)
	}

	tests := []struct {
		name    string
		tlsMode token.TLSClientMode
		cancel  *pgproto3.CancelRequest
		serve   func(t *testing.T, conn net.Conn)
		wantErr error
	}{
		{
			name:    "plaintext",
			tlsMode: token.TLSClientModeNone,
			serve: func(t *testing.T, conn net.Conn) {
				t.Helper()

				receiveCancel(t, conn)
				require.NoError(t, conn.Close())
			},
		},
		{
			name:    "over TLS",
			tlsMode: token.TLSClientModeVerifyCA,
			serve: func(t *testing.T, conn net.Conn) {
				t.Helper()

				tlsConn := acceptTLS(t, conn)
				receiveCancel(t, tlsConn)
				require.NoError(t, tlsConn.Close())
			},
		},
		{
			name:    "upstream refuses TLS",
			tlsMode: token.TLSClientModeVerifyCA,
			serve:   refuseTLS,
			wantErr: errTLSRejected,
		},
		{
			name:    "upstream resets the connection after the cancel",
			tlsMode: token.TLSClientModeNone,
			serve: func(t *testing.T, conn net.Conn) {
				t.Helper()

				receiveCancel(t, conn)

				tcpConn, ok := conn.(*net.TCPConn)
				require.True(t, ok)
				require.NoError(t, tcpConn.SetLinger(0))
				require.NoError(t, tcpConn.Close())
			},
			wantErr: errFailedToSendCancelRequest,
		},
		{
			name:    "cancel request fails to encode",
			tlsMode: token.TLSClientModeNone,
			cancel:  &pgproto3.CancelRequest{ProcessID: 42, SecretKey: make([]byte, 257)},
			serve: func(t *testing.T, conn net.Conn) {
				t.Helper()

				_, err := conn.Read(make([]byte, 1))
				assert.ErrorIs(t, err, io.EOF)
			},
			wantErr: errFailedToSendCancelRequest,
		},
		{
			name:    "upstream unreachable",
			tlsMode: token.TLSClientModeNone,
			wantErr: errFailedToConnectUpstream,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, address := newUpstreamListener(t)
			if tt.serve == nil {
				require.NoError(t, listener.Close())
			}

			request := cancel
			if tt.cancel != nil {
				request = tt.cancel
			}

			caPool := newTestCAPool(t)
			done := make(chan error, 1)

			go func() {
				done <- cancelUpstream(newProxyConn(nil, address, tt.tlsMode, passwordAuth), request, caPool)
			}()

			if tt.serve != nil {
				tt.serve(t, acceptUpstream(t, listener))
			}

			require.ErrorIs(t, <-done, tt.wantErr)
		})
	}
}

func TestStartTLS(t *testing.T) {
	tests := []struct {
		name    string
		serve   func(t *testing.T, conn net.Conn)
		wantErr error
	}{
		{
			name: "upstream accepts TLS",
			serve: func(t *testing.T, conn net.Conn) {
				t.Helper()

				require.NoError(t, acceptTLS(t, conn).Handshake())
			},
		},
		{
			name:    "upstream refuses TLS",
			serve:   refuseTLS,
			wantErr: errTLSRejected,
		},
		{
			name: "upstream closes before the SSLRequest",
			serve: func(t *testing.T, conn net.Conn) {
				t.Helper()

				require.NoError(t, conn.Close())
			},
			wantErr: io.ErrClosedPipe,
		},
		{
			name: "upstream closes before answering the SSLRequest",
			serve: func(t *testing.T, conn net.Conn) {
				t.Helper()

				msg, err := pgproto3.NewBackend(conn, conn).ReceiveStartupMessage()
				require.NoError(t, err)
				require.IsType(t, &pgproto3.SSLRequest{}, msg)
				require.NoError(t, conn.Close())
			},
			wantErr: io.EOF,
		},
		{
			name: "upstream closes during the TLS handshake",
			serve: func(t *testing.T, conn net.Conn) {
				t.Helper()

				msg, err := pgproto3.NewBackend(conn, conn).ReceiveStartupMessage()
				require.NoError(t, err)
				require.IsType(t, &pgproto3.SSLRequest{}, msg)

				_, err = conn.Write([]byte{sslAccepted})
				require.NoError(t, err)
				require.NoError(t, conn.Close())
			},
			wantErr: io.ErrClosedPipe,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()

			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})

			tlsConfig := &tls.Config{RootCAs: newTestCAPool(t), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
			done := make(chan error, 1)

			go func() {
				_, err := startTLS(clientConn, tlsConfig)
				done <- err
			}()

			tt.serve(t, serverConn)

			require.ErrorIs(t, <-done, tt.wantErr)
		})
	}
}
