// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	backendtls "gateway/internal/backend/tls"
	gatewayconfig "gateway/internal/config"
	"gateway/internal/token"
)

func TestNewUpstream(t *testing.T) {
	got := newUpstream("db.acme.int:5432", &tls.Config{MinVersion: tls.VersionTLS12})

	assert.Equal(t, "db.acme.int", got.tlsConfig.ServerName)
}

func TestUpstream_ConnectConfig(t *testing.T) {
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

	tests := []struct {
		name         string
		setup        func(u *upstream, params map[string]string, cred *credential)
		wantDatabase string
		wantErr      error
	}{
		{
			name:         "database from the startup message",
			setup:        func(*upstream, map[string]string, *credential) {},
			wantDatabase: "app",
		},
		{
			name: "URL characters in the user, password and database",
			setup: func(_ *upstream, params map[string]string, cred *credential) {
				cred.user = "app@acme"
				cred.password = "p@ss:w/rd?#%"
				params["database"] = "/app/db?x"
			},
			wantDatabase: "/app/db?x",
		},
		{
			name:         "no database falls back to the credential's user",
			setup:        func(_ *upstream, params map[string]string, _ *credential) { delete(params, "database") },
			wantDatabase: testDatabaseUser,
		},
		{
			name:    "empty password",
			setup:   func(_ *upstream, _ map[string]string, cred *credential) { cred.password = "" },
			wantErr: errEmptyPassword,
		},
		{
			name:    "port out of range",
			setup:   func(u *upstream, _ map[string]string, _ *credential) { u.address = "db.acme.int:65536" },
			wantErr: errFailedToConnectUpstream,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := upstream{address: "db.acme.int:5432"}
			startup := &pgproto3.StartupMessage{
				ProtocolVersion: pgproto3.ProtocolVersion30,
				Parameters: map[string]string{
					"user":             "alice", // Dropped in favor of the credential's user.
					"database":         "app",
					"application_name": "psql",
					"replication":      "database",
					"_pq_.test_option": "on",
				},
			}
			cred := credential{user: testDatabaseUser, password: "secret", requireAuth: "scram-sha-256"}
			tt.setup(&u, startup.Parameters, &cred)

			config, err := u.connectConfig(startup, cred)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)

			assert.Equal(t, cred.user, config.User)
			assert.Equal(t, cred.password, config.Password)
			assert.Equal(t, "db.acme.int", config.Host)
			assert.EqualValues(t, 5432, config.Port)
			assert.Equal(t, tt.wantDatabase, config.Database)
			assert.Empty(t, config.Fallbacks)
			assert.Equal(t, map[string]string{"application_name": "psql"}, config.RuntimeParams)
			assert.Equal(t, "postgres", config.SSLNegotiation)
			assert.Equal(t, "3.0", config.MinProtocolVersion)
			assert.Equal(t, "3.0", config.MaxProtocolVersion)
			assert.Equal(t, "prefer", config.ChannelBinding)
			assert.Equal(t, cred.requireAuth, config.RequireAuth)
		})
	}
}

func TestUpstream_ConnectConfig_ConnectTimeout(t *testing.T) {
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

			config, err := upstream{address: "db.acme.int:5432"}.connectConfig(
				&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30},
				credential{user: testDatabaseUser, password: "secret"},
			)

			require.NoError(t, err)
			assert.Equal(t, tt.want, config.ConnectTimeout)
		})
	}
}

func TestUpstream_ConnectConfig_TLS(t *testing.T) {
	certificate := &tls.Certificate{Certificate: [][]byte{{1}}}

	tests := []struct {
		name             string
		tlsConfig        *tls.Config
		certificate      *tls.Certificate
		wantCertificates []tls.Certificate
	}{
		{name: "plaintext ignores the client certificate", certificate: certificate},
		{name: "TLS, no client certificate", tlsConfig: &tls.Config{ServerName: "db.acme.int", MinVersion: tls.VersionTLS12}},
		{name: "TLS, client certificate", tlsConfig: &tls.Config{ServerName: "db.acme.int", MinVersion: tls.VersionTLS12}, certificate: certificate, wantCertificates: []tls.Certificate{*certificate}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := upstream{address: "db.acme.int:5432", tlsConfig: tt.tlsConfig}

			config, err := u.connectConfig(
				&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30},
				credential{user: testDatabaseUser, password: "secret", certificate: tt.certificate},
			)
			require.NoError(t, err)

			if tt.tlsConfig == nil {
				assert.Nil(t, config.TLSConfig)

				return
			}

			require.NotNil(t, config.TLSConfig)
			assert.Equal(t, "db.acme.int", config.TLSConfig.ServerName)
			assert.Equal(t, tt.wantCertificates, config.TLSConfig.Certificates)
			assert.Empty(t, u.tlsConfig.Certificates)
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

func TestUpstream_Connect_Success(t *testing.T) {
	type result struct {
		dbConn *pgconn.HijackedConn
		err    error
	}

	listener, address := newUpstreamListener(t)
	u := upstream{
		address:   address,
		tlsConfig: &tls.Config{RootCAs: newTestCAPool(t), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12},
	}
	startup := &pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters:      map[string]string{"user": "alice", "database": "app", "application_name": "psql"},
	}
	cred := credential{user: testDatabaseUser, password: "secret", requireAuth: "password"}

	done := make(chan result, 1)

	go func() {
		hijackedConn, err := u.connect(t.Context(), startup, cred)
		done <- result{dbConn: hijackedConn, err: err}
	}()

	// The database agrees to TLS, then asks for a cleartext password and accepts it.
	conn := acceptUpstream(t, listener)
	tlsConn := acceptTLS(t, conn)
	backend := pgproto3.NewBackend(tlsConn, tlsConn)
	received, err := backend.ReceiveStartupMessage()
	require.NoError(t, err)
	assert.Equal(t, &pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters:      map[string]string{"user": testDatabaseUser, "database": "app", "application_name": "psql"},
	}, received)

	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	require.NoError(t, backend.Flush())

	msg, err := backend.Receive()
	require.NoError(t, err)
	assert.Equal(t, &pgproto3.PasswordMessage{Password: "secret"}, msg)

	for _, msg := range loginMessages {
		backend.Send(msg)
	}

	require.NoError(t, backend.Flush())

	res := <-done
	require.NoError(t, res.err)

	t.Cleanup(func() { _ = res.dbConn.Conn.Close() })

	assert.EqualValues(t, 42, res.dbConn.PID)
	assert.Equal(t, []byte{1, 2, 3, 4}, res.dbConn.SecretKey)
	assert.Equal(t, map[string]string{"server_version": "17.0"}, res.dbConn.ParameterStatuses)
	assert.EqualValues(t, 'I', res.dbConn.TxStatus)
}

func TestUpstream_Connect_Error(t *testing.T) {
	startup := &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30}

	t.Run("upstream unreachable", func(t *testing.T) {
		listener, address := newUpstreamListener(t)
		require.NoError(t, listener.Close())

		_, err := upstream{address: address}.connect(t.Context(), startup, credential{user: testDatabaseUser, password: "secret"})

		require.ErrorIs(t, err, errFailedToConnectUpstream)
	})

	t.Run("empty password", func(t *testing.T) {
		_, err := upstream{address: "db.acme.int:5432"}.connect(t.Context(), startup, credential{user: testDatabaseUser})

		require.ErrorIs(t, err, errEmptyPassword)
	})
}

func TestUpstream_ForwardCancelRequest(t *testing.T) {
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

			u := newUpstream(address, backendtls.NewUpstreamTLSConfig(tt.tlsMode, newTestCAPool(t)))
			done := make(chan error, 1)

			go func() {
				done <- u.forwardCancelRequest(t.Context(), request)
			}()

			if tt.serve != nil {
				tt.serve(t, acceptUpstream(t, listener))
			}

			require.ErrorIs(t, <-done, tt.wantErr)
		})
	}
}

func TestUpstream_ForwardCancelRequest_ContextCanceled(t *testing.T) {
	cancel := &pgproto3.CancelRequest{ProcessID: 42, SecretKey: []byte{1, 2, 3, 4}}

	t.Run("before dialing", func(t *testing.T) {
		_, address := newUpstreamListener(t)
		ctx, cancelCtx := context.WithCancel(t.Context())
		cancelCtx()

		err := newUpstream(address, nil).forwardCancelRequest(ctx, cancel)

		require.ErrorIs(t, err, errFailedToConnectUpstream)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("while waiting for the database", func(t *testing.T) {
		listener, address := newUpstreamListener(t)
		u := newUpstream(address, backendtls.NewUpstreamTLSConfig(token.TLSClientModeVerifyCA, newTestCAPool(t)))
		ctx, cancelCtx := context.WithCancel(t.Context())
		done := make(chan error, 1)

		go func() {
			done <- u.forwardCancelRequest(ctx, cancel)
		}()

		// The database receives the request but never closes the connection.
		tlsConn := acceptTLS(t, acceptUpstream(t, listener))
		_, err := pgproto3.NewBackend(tlsConn, tlsConn).ReceiveStartupMessage()
		require.NoError(t, err)

		cancelCtx()

		err = <-done
		require.ErrorIs(t, err, errFailedToSendCancelRequest)
		require.ErrorIs(t, err, net.ErrClosed)
	})
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
