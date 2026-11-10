// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"crypto/tls"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	zapobserver "go.uber.org/zap/zaptest/observer"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/frontend"
	"gateway/internal/logging"
	"gateway/internal/token"
)

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

// newTestProxy builds a proxy whose trust store holds the test certificate, which the fake
// upstreams serve. Besides the test credential, it has an "unreadable" credential whose password
// file does not exist.
func newTestProxy(t *testing.T) *Proxy {
	t.Helper()

	config, err := NewConfig(&gatewayconfig.PostgreSQLConfig{
		Credentials: []gatewayconfig.PostgreSQLCredential{
			{Name: testCredential, Password: "secret"},
			{Name: "unreadable", PasswordFile: filepath.Join(t.TempDir(), "missing")},
		},
	}, []gatewayconfig.UpstreamTrustedCABundle{{File: testCertificateFile}}, logging.NewNop())
	require.NoError(t, err)

	return NewProxy(*config)
}

// receiveStartup reads the proxy's StartupMessage on an accepted upstream connection.
func receiveStartup(t *testing.T, conn net.Conn) (*pgproto3.StartupMessage, *pgproto3.Backend) {
	t.Helper()

	backend := pgproto3.NewBackend(conn, conn)

	msg, err := backend.ReceiveStartupMessage()
	require.NoError(t, err)

	startup, ok := msg.(*pgproto3.StartupMessage)
	require.True(t, ok, "expected a StartupMessage, got %T", msg)

	return startup, backend
}

// acceptAuthentication reads the proxy's StartupMessage on an accepted upstream connection, asks for a
// cleartext password, and accepts the session.
func acceptAuthentication(t *testing.T, conn net.Conn) *pgproto3.Backend {
	t.Helper()

	startup, backend := receiveStartup(t, conn)
	assert.Equal(t, testDatabaseUser, startup.Parameters["user"])

	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	require.NoError(t, backend.Flush())

	msg, err := backend.Receive()
	require.NoError(t, err)
	assert.Equal(t, &pgproto3.PasswordMessage{Password: awsIAMPlaceholder}, msg)

	for _, msg := range loginMessages {
		backend.Send(msg)
	}

	require.NoError(t, backend.Flush())

	return backend
}

// testSession is a connection served by a test proxy.
type testSession struct {
	proxy      *Proxy
	client     *pgproto3.Frontend
	clientConn net.Conn
	server     *pgproto3.Backend
	serverConn net.Conn
	done       <-chan error
}

var awsIAMAuth = token.Auth{
	Type:   token.AuthTypeAWSIAM,
	User:   testDatabaseUser,
	AWSIAM: &token.AWSIAMAuth{Region: "eu-west-1"},
}

// newEstablishedSession returns a session whose client is logged in to a fake database, with
// the proxy relaying between them. It logs in with the aws_iam auth type, whose token is sent
// as a cleartext password that the fake database accepts.
func newEstablishedSession(t *testing.T, tlsMode token.TLSClientMode) *testSession {
	t.Helper()

	listener, address := newUpstreamListener(t)
	session := newSession(t, address, tlsMode, awsIAMAuth)
	sendStartup(t, session.client)

	upstreamConn := acceptUpstream(t, listener)
	if tlsMode != token.TLSClientModeNone {
		upstreamConn = acceptTLS(t, upstreamConn)
	}

	upstream := acceptAuthentication(t, upstreamConn)

	// The client sees the session state the upstream authentication consumed.
	for _, want := range loginMessages {
		got, err := session.client.Receive()
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}

	session.server = upstream
	session.serverConn = upstreamConn

	return session
}

// newSession starts serving a new client connection. The client has sent nothing yet, and the
// test plays the database at address, if there is one.
func newSession(t *testing.T, address string, tlsMode token.TLSClientMode, auth token.Auth) *testSession {
	t.Helper()

	proxy := newTestProxy(t)
	clientConn, serverConn := tcpPipe(t)
	proxyConn := newProxyConn(serverConn, address, tlsMode, auth)
	done := make(chan error, 1)

	go func() {
		done <- proxy.serveConn(t.Context(), proxyConn)
	}()

	return &testSession{
		proxy:      proxy,
		client:     pgproto3.NewFrontend(clientConn, clientConn),
		clientConn: clientConn,
		done:       done,
	}
}

// closedAddr returns the address of a listener that no longer accepts connections.
func closedAddr(t *testing.T) string {
	t.Helper()

	listener, address := newUpstreamListener(t)
	require.NoError(t, listener.Close())

	return address
}

func connCount(proxy *Proxy) int {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()

	return len(proxy.conns)
}

// assertRejected checks that the client gets the ErrorResponse for the error serveConn returned,
// then the connection closes.
func assertRejected(t *testing.T, session *testSession, err error) {
	t.Helper()

	want := newErrorResponse(err)

	got, err := session.client.Receive()
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assertEOF(t, session.clientConn)
}

func sendStartup(t *testing.T, client *pgproto3.Frontend) {
	t.Helper()

	client.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30, Parameters: map[string]string{"user": "alice"}})
	require.NoError(t, client.Flush())
}

func TestCloseOnPanic_CleanupPanicRecovered(t *testing.T) {
	// closeOnPanic is the outermost defer in every serving goroutine, so a panic in its
	// cleanup must be recovered too rather than escape and crash the process.
	core, logs := zapobserver.New(zap.ErrorLevel)
	logger := zap.New(core)

	require.NotPanics(t, func() {
		defer closeOnPanic(logger, func() { panic("cleanup boom") })

		panic("serve boom")
	})

	assert.Equal(t, 2, logs.Len())
	assert.Equal(t, "Recovered from panic", logs.All()[0].Message)
	assert.Equal(t, "Recovered from panic during cleanup", logs.All()[1].Message)
}

func TestProxy_RejectsWhenShuttingDown(t *testing.T) {
	proxy := newTestProxy(t)
	proxy.Shutdown(t.Context())

	clientConn, serverConn := net.Pipe()

	require.ErrorIs(t, proxy.serveConn(t.Context(), newProxyConn(serverConn, "unused:5432", token.TLSClientModeNone, passwordAuth)), errShuttingDown)
	assertEOF(t, clientConn)
}

func TestProxy_Start_ServesUntilListenerCloses(t *testing.T) {
	// A shut-down proxy closes every connection it serves, so the client seeing EOF shows the
	// accepted connection reached the proxy.
	proxy := newTestProxy(t)
	proxy.Shutdown(t.Context())

	conns := make(chan frontend.Conn)
	listener := frontend.NewProtocolListener(conns, nil)
	done := make(chan error, 1)

	go func() {
		done <- proxy.Start(t.Context(), listener)
	}()

	clientConn, serverConn := net.Pipe()
	conns <- newProxyConn(serverConn, "unused:5432", token.TLSClientModeNone, passwordAuth)

	assertEOF(t, clientConn)

	require.NoError(t, listener.Close())
	require.NoError(t, waitServe(t, done))
}

func TestProxy_ServeConn(t *testing.T) {
	session := newEstablishedSession(t, token.TLSClientModeNone)

	// A query round trip through the relay.
	session.client.Send(&pgproto3.Query{String: "SELECT 1"})
	require.NoError(t, session.client.Flush())

	got, err := session.server.Receive()
	require.NoError(t, err)
	assert.Equal(t, &pgproto3.Query{String: "SELECT 1"}, got)

	session.server.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
	session.server.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	require.NoError(t, session.server.Flush())

	for _, want := range []pgproto3.BackendMessage{&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'}} {
		got, err := session.client.Receive()
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}

	// Terminate reaches the upstream, which closes its side, and the session ends normally.
	session.client.Send(&pgproto3.Terminate{})
	require.NoError(t, session.client.Flush())

	got, err = session.server.Receive()
	require.NoError(t, err)
	assert.IsType(t, &pgproto3.Terminate{}, got)
	require.NoError(t, session.serverConn.Close())

	require.NoError(t, waitServe(t, session.done))
	assertEOF(t, session.clientConn)
}

// TestProxy_ServeConn_TLS authenticates over TLS, verifying the upstream certificate.
func TestProxy_ServeConn_TLS(t *testing.T) {
	session := newEstablishedSession(t, token.TLSClientModeVerifyFull)

	_, ok := session.serverConn.(*tls.Conn)
	require.True(t, ok)

	session.client.Send(&pgproto3.Terminate{})
	require.NoError(t, session.client.Flush())

	got, err := session.server.Receive()
	require.NoError(t, err)
	assert.IsType(t, &pgproto3.Terminate{}, got)
	require.NoError(t, session.serverConn.Close())

	require.NoError(t, waitServe(t, session.done))
	assertEOF(t, session.clientConn)
}

func TestProxy_ServeConn_StartupError(t *testing.T) {
	session := newSession(t, "unused:5432", token.TLSClientModeNone, passwordAuth)

	session.client.Send(&pgproto3.SSLRequest{})
	session.client.Send(&pgproto3.SSLRequest{})
	require.NoError(t, session.client.Flush())

	// Only the first SSLRequest is answered.
	negotiated := make([]byte, 1)
	_, err := io.ReadFull(session.clientConn, negotiated)
	require.NoError(t, err)
	assert.Equal(t, []byte("N"), negotiated)

	err = waitServe(t, session.done)
	require.ErrorIs(t, err, errUnsupportedStartupRequest)
	assertRejected(t, session, err)
}

// TestProxy_ServeConn_NegotiatesProtocolFirst checks that the protocol version is negotiated
// before any work is done upstream.
func TestProxy_ServeConn_NegotiatesProtocolFirst(t *testing.T) {
	auth := token.Auth{Type: token.AuthTypePassword, User: testDatabaseUser, Password: &token.PasswordAuth{Credential: "other"}}
	session := newSession(t, "unused:5432", token.TLSClientModeNone, auth)

	session.client.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion32, Parameters: map[string]string{"user": "alice"}})
	require.NoError(t, session.client.Flush())

	got, err := session.client.Receive()
	require.NoError(t, err)
	assert.Equal(t, &pgproto3.NegotiateProtocolVersion{NewestMinorProtocol: pgproto3.ProtocolVersion30, UnrecognizedOptions: []string{}}, got)

	err = waitServe(t, session.done)
	require.ErrorIs(t, err, errFailedToGetCredential)
	assertRejected(t, session, err)
}

// The client hangs up right after its StartupMessage, and net.Pipe fails the proxy's next write.
func TestProxy_ServeConn_NegotiateProtocolFails(t *testing.T) {
	proxy := newTestProxy(t)
	clientConn, serverConn := net.Pipe()
	done := make(chan error, 1)

	go func() {
		done <- proxy.serveConn(t.Context(), newProxyConn(serverConn, "unused:5432", token.TLSClientModeNone, passwordAuth))
	}()

	client := pgproto3.NewFrontend(clientConn, clientConn)
	client.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion32, Parameters: map[string]string{"user": "alice"}})
	require.NoError(t, client.Flush())
	require.NoError(t, clientConn.Close())

	require.ErrorIs(t, waitServe(t, done), errFailedToNegotiateProtocol)
}

// The client hangs up right after its StartupMessage, and net.Pipe fails the proxy's next write.
func TestProxy_ServeConn_CompleteLoginFails(t *testing.T) {
	listener, address := newUpstreamListener(t)
	proxy := newTestProxy(t)
	clientConn, serverConn := net.Pipe()
	done := make(chan error, 1)

	go func() {
		done <- proxy.serveConn(t.Context(), newProxyConn(serverConn, address, token.TLSClientModeNone, awsIAMAuth))
	}()

	sendStartup(t, pgproto3.NewFrontend(clientConn, clientConn))
	require.NoError(t, clientConn.Close())

	acceptAuthentication(t, acceptUpstream(t, listener))

	require.ErrorIs(t, waitServe(t, done), errFailedToCompleteLogin)
}

func TestProxy_ServeConn_CredentialError(t *testing.T) {
	tests := []struct {
		name       string
		credential string
	}{
		{name: "unknown credential", credential: "other"},
		{name: "credential fails to load", credential: "unreadable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := token.Auth{Type: token.AuthTypePassword, User: testDatabaseUser, Password: &token.PasswordAuth{Credential: tt.credential}}
			session := newSession(t, "unused:5432", token.TLSClientModeNone, auth)
			sendStartup(t, session.client)

			err := waitServe(t, session.done)
			require.ErrorIs(t, err, errFailedToGetCredential)
			assertRejected(t, session, err)
		})
	}
}

func TestProxy_ServeConn_UpstreamUnreachable(t *testing.T) {
	session := newSession(t, closedAddr(t), token.TLSClientModeNone, passwordAuth)
	sendStartup(t, session.client)

	require.ErrorIs(t, waitServe(t, session.done), errFailedToConnectUpstream)
	assertRejected(t, session, errFailedToConnectUpstream)
}

func TestProxy_ServeConn_UpstreamError(t *testing.T) {
	tests := []struct {
		name     string
		tlsMode  token.TLSClientMode
		upstream func(t *testing.T, conn net.Conn)
	}{
		{
			name:    "upstream refuses TLS",
			tlsMode: token.TLSClientModeVerifyFull,
			upstream: func(t *testing.T, conn net.Conn) {
				t.Helper()

				refuseTLS(t, conn)
			},
		},
		{
			// The password auth type authenticates with SCRAM only.
			name:    "authentication method refused",
			tlsMode: token.TLSClientModeNone,
			upstream: func(t *testing.T, conn net.Conn) {
				t.Helper()

				_, backend := receiveStartup(t, conn)
				backend.Send(&pgproto3.AuthenticationCleartextPassword{})
				require.NoError(t, backend.Flush())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, address := newUpstreamListener(t)
			session := newSession(t, address, tt.tlsMode, passwordAuth)
			sendStartup(t, session.client)

			tt.upstream(t, acceptUpstream(t, listener))

			require.ErrorIs(t, waitServe(t, session.done), errFailedToConnectUpstream)
			assertRejected(t, session, errFailedToConnectUpstream)
		})
	}
}

func TestProxy_ServeConn_AuthenticationRefused(t *testing.T) {
	listener, address := newUpstreamListener(t)
	session := newSession(t, address, token.TLSClientModeNone, passwordAuth)
	sendStartup(t, session.client)

	_, backend := receiveStartup(t, acceptUpstream(t, listener))
	backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"})
	require.NoError(t, backend.Flush())

	var pgErr *pgconn.PgError

	err := waitServe(t, session.done)
	require.ErrorAs(t, err, &pgErr)
	assert.Equal(t, "28P01", pgErr.Code)
	assertRejected(t, session, err)
}

func TestProxy_ServeConn_Cancel(t *testing.T) {
	listener, address := newUpstreamListener(t)
	session := newSession(t, address, token.TLSClientModeNone, passwordAuth)

	cancel := &pgproto3.CancelRequest{ProcessID: 42, SecretKey: []byte{1, 2, 3, 4}}
	session.client.Send(cancel)
	require.NoError(t, session.client.Flush())

	upstreamConn := acceptUpstream(t, listener)

	got, err := pgproto3.NewBackend(upstreamConn, upstreamConn).ReceiveStartupMessage()
	require.NoError(t, err)
	assert.Equal(t, cancel, got)

	// The database answers a cancel request by closing the connection.
	require.NoError(t, upstreamConn.Close())

	require.NoError(t, waitServe(t, session.done))
	assertEOF(t, session.clientConn)
}

func TestProxy_ServeConn_CancelFails(t *testing.T) {
	session := newSession(t, closedAddr(t), token.TLSClientModeNone, passwordAuth)

	session.client.Send(&pgproto3.CancelRequest{ProcessID: 42, SecretKey: []byte{1, 2, 3, 4}})
	require.NoError(t, session.client.Flush())

	require.ErrorIs(t, waitServe(t, session.done), errFailedToConnectUpstream)
	assertEOF(t, session.clientConn)
}

func TestProxy_Shutdown_ClosesActiveConnection(t *testing.T) {
	session := newEstablishedSession(t, token.TLSClientModeNone)

	require.Eventually(t, func() bool {
		return connCount(session.proxy) == 1
	}, testTimeout, 10*time.Millisecond, "connection was not tracked")

	session.proxy.Shutdown(t.Context())

	require.NoError(t, waitServe(t, session.done))
	assertEOF(t, session.clientConn)
	assertEOF(t, session.serverConn)
	assert.Zero(t, connCount(session.proxy))
}

func TestProxy_Shutdown_ClosesConnectionInStartup(t *testing.T) {
	// The client never sends a startup packet, so only Shutdown can end the connection
	// before the startup deadline.
	session := newSession(t, "unused:5432", token.TLSClientModeNone, passwordAuth)

	require.Eventually(t, func() bool {
		return connCount(session.proxy) == 1
	}, testTimeout, 10*time.Millisecond, "connection was not tracked")

	session.proxy.Shutdown(t.Context())

	require.ErrorIs(t, waitServe(t, session.done), errFailedToReceiveStartup)
	assertEOF(t, session.clientConn)
	assert.Zero(t, connCount(session.proxy))
}
