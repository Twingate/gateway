// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"gateway/internal/logging"
	"gateway/internal/token"
)

const (
	testUpstreamAddress = "10.0.0.1:5432"
	testUpstreamUser    = "gateway_svc"
	testUpstreamPass    = "s3cret"
	testCredential      = "prod-svc"
)

// mockDialer returns a preset upstream connection on DialTimeout.
type mockDialer struct {
	mu      sync.Mutex
	conns   []net.Conn
	lastErr error
}

func (m *mockDialer) DialTimeout(_, _ string, _ time.Duration) (net.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lastErr != nil {
		return nil, m.lastErr
	}

	if len(m.conns) == 0 {
		return nil, errNoConnsQueued
	}

	c := m.conns[0]
	m.conns = m.conns[1:]

	return c, nil
}

func (m *mockDialer) setNextConn(c net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.conns = append(m.conns, c)
}

func (m *mockDialer) setErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.lastErr = err
}

var errNoConnsQueued = errors.New("no upstream conns queued")

// proxyConnFake implements connect.Conn by wrapping a net.Conn and hard-coding
// claims / address / id.
type proxyConnFake struct {
	net.Conn

	claims        *token.GATClaims
	id            string
	requestedHost string
	address       string
	closeOnce     sync.Once
	closed        chan struct{}
}

func newProxyConnFake(conn net.Conn) *proxyConnFake {
	host, _, _ := net.SplitHostPort(testUpstreamAddress)

	return &proxyConnFake{
		Conn: conn,
		claims: &token.GATClaims{
			User: token.User{ID: "u", Username: "alice@acme"},
			Resource: token.Resource{
				Type:    token.ResourceTypePostgres,
				Address: testUpstreamAddress,
				GatewayMetadata: token.GatewayMetadata{
					Auths: []token.Auth{
						{Type: token.AuthTypePassword, User: testUpstreamUser, Credential: testCredential},
					},
				},
			},
		},
		id:            "test-conn-id",
		requestedHost: host,
		address:       testUpstreamAddress,
		closed:        make(chan struct{}),
	}
}

func (p *proxyConnFake) GATClaims() *token.GATClaims { return p.claims }
func (p *proxyConnFake) GetID() string               { return p.id }
func (p *proxyConnFake) GetRequestedHost() string    { return p.requestedHost }
func (p *proxyConnFake) GetUpstreamAddress() string  { return p.address }
func (p *proxyConnFake) GetToken() string            { return "" }
func (p *proxyConnFake) Authenticate() error         { return nil }
func (p *proxyConnFake) UpgradeToTLS() error         { return nil }

func (p *proxyConnFake) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })

	return p.Conn.Close()
}

func newTestProxy(t *testing.T) (*Proxy, *mockDialer) {
	t.Helper()

	p := NewProxy(Config{
		passwordsByCredential: map[string]string{testCredential: testUpstreamPass},
		logger:                logging.NewNop(),
	})

	md := &mockDialer{}
	p.netDialer = md

	return p, md
}

func TestProxy_Serve_AuthResolutionFailure(t *testing.T) {
	tests := []struct {
		name    string
		auths   []token.Auth
		wantErr error
	}{
		{
			name:    "no auths",
			auths:   nil,
			wantErr: errNoAuth,
		},
		{
			name:    "unknown credential",
			auths:   []token.Auth{{Type: token.AuthTypePassword, User: testUpstreamUser, Credential: "missing"}},
			wantErr: errUnknownCredential,
		},
		{
			name:    "unsupported auth type",
			auths:   []token.Auth{{Type: token.AuthTypeAWSIAM, User: testUpstreamUser, Region: "us-east-1"}},
			wantErr: errUnsupportedAuth,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := newTestProxy(t)

			clientSide, proxySide := net.Pipe()
			conn := newProxyConnFake(proxySide)
			conn.claims.Resource.GatewayMetadata.Auths = tt.auths

			done := make(chan error, 1)

			go func() { done <- p.Serve(t.Context(), conn) }()

			client := pgproto3.NewFrontend(clientSide, clientSide)
			client.Send(&pgproto3.StartupMessage{
				ProtocolVersion: pgproto3.ProtocolVersionNumber,
				Parameters:      map[string]string{"user": "alice", "database": "app"},
			})
			require.NoError(t, client.Flush())

			msg, err := client.Receive()
			require.NoError(t, err)

			errResp, ok := msg.(*pgproto3.ErrorResponse)
			require.True(t, ok, "got %T", msg)
			assert.Equal(t, "28000", errResp.Code)

			_ = clientSide.Close()

			select {
			case err := <-done:
				require.ErrorIs(t, err, tt.wantErr)
			case <-time.After(2 * time.Second):
				t.Fatal("Serve did not return")
			}
		})
	}
}

func TestProxy_Serve_DialFailure(t *testing.T) {
	p, md := newTestProxy(t)
	md.setErr(errors.New("boom"))

	clientSide, proxySide := net.Pipe()
	conn := newProxyConnFake(proxySide)

	// Client sends a StartupMessage; expect an ErrorResponse back.
	done := make(chan error, 1)

	go func() { done <- p.Serve(t.Context(), conn) }()

	client := pgproto3.NewFrontend(clientSide, clientSide)
	client.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "alice", "database": "app"},
	})
	require.NoError(t, client.Flush())

	msg, err := client.Receive()
	require.NoError(t, err)

	errResp, ok := msg.(*pgproto3.ErrorResponse)
	require.True(t, ok, "got %T", msg)
	assert.Equal(t, "08006", errResp.Code)

	_ = clientSide.Close()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// TestProxy_Serve_HappyPath drives a full connection end-to-end:
// client sends SSLRequest → gets 'N' → sends StartupMessage → sees AuthOk →
// sends a Query, which reaches the scripted upstream → upstream replies,
// which reaches the client.
func TestProxy_Serve_HappyPath(t *testing.T) {
	p, md := newTestProxy(t)

	// Client side (simulating Twingate client → gateway)
	clientSide, proxyClientSide := net.Pipe()
	// Upstream side (simulating gateway → PG server)
	upstreamServerSide, upstreamClientSide := net.Pipe()
	md.setNextConn(upstreamClientSide)

	conn := newProxyConnFake(proxyClientSide)

	// Spin up the upstream-PG simulator
	upstreamDone := make(chan error, 1)

	go func() {
		upstreamDone <- runFakeUpstream(upstreamServerSide)
	}()

	// Spin up the proxy
	serveDone := make(chan error, 1)

	go func() {
		serveDone <- p.Serve(t.Context(), conn)
	}()

	// Client side script
	clientErr := runClientScript(clientSide)

	// Close client side to let proxy.Serve exit.
	_ = clientSide.Close()

	select {
	case <-serveDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}

	select {
	case err := <-upstreamDone:
		require.NoError(t, err, "upstream script failed")
	case <-time.After(2 * time.Second):
		t.Fatal("upstream script hung")
	}

	require.NoError(t, clientErr)
}

// runClientScript acts as a Postgres client: sends SSLRequest (expects 'N'),
// sends StartupMessage, expects AuthOk → ReadyForQuery, sends a Query, expects
// a CommandComplete.
func runClientScript(conn net.Conn) error {
	// SSLRequest is sent as a raw 8-byte preamble before we switch to pgproto3.
	sslReq, err := (&pgproto3.SSLRequest{}).Encode(nil)
	if err != nil {
		return err
	}

	if _, err := conn.Write(sslReq); err != nil {
		return err
	}

	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		return err
	}

	if buf[0] != 'N' {
		return errSSLExpectedN
	}

	frontend := pgproto3.NewFrontend(conn, conn)
	frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "alice", "database": "app"},
	})

	if err := frontend.Flush(); err != nil {
		return err
	}

	// Expect AuthenticationOk, ReadyForQuery (forwarded from upstream).
	sawAuthOk := false
	sawReady := false

	for !sawAuthOk || !sawReady {
		msg, err := frontend.Receive()
		if err != nil {
			return err
		}

		switch msg.(type) {
		case *pgproto3.AuthenticationOk:
			sawAuthOk = true
		case *pgproto3.ReadyForQuery:
			sawReady = true
		case *pgproto3.ParameterStatus, *pgproto3.BackendKeyData:
			// ignore
		default:
			// noise is fine
		}
	}

	// Send a query, expect CommandComplete and another ReadyForQuery
	frontend.Send(&pgproto3.Query{String: "SELECT 1"})

	if err := frontend.Flush(); err != nil {
		return err
	}

	for {
		msg, err := frontend.Receive()
		if err != nil {
			return err
		}

		if _, ok := msg.(*pgproto3.CommandComplete); ok {
			return nil
		}
	}
}

var errSSLExpectedN = errors.New("expected 'N' response to SSLRequest")

// runFakeUpstream plays the server side of the upstream PG connection:
// expects StartupMessage (with user overridden to gateway_svc, database=app),
// issues cleartext password challenge, accepts the password, then handles one
// Query → CommandComplete → ReadyForQuery.
func runFakeUpstream(conn net.Conn) error {
	backend := pgproto3.NewBackend(conn, conn)

	startupMsg, err := backend.ReceiveStartupMessage()
	if err != nil {
		return err
	}

	startup, ok := startupMsg.(*pgproto3.StartupMessage)
	if !ok {
		return errUpstreamExpectedStartup
	}

	if got := startup.Parameters["user"]; got != testUpstreamUser {
		return &assertError{what: "user", got: got, want: testUpstreamUser}
	}

	if got := startup.Parameters["database"]; got != "app" {
		return &assertError{what: "database", got: got, want: "app"}
	}

	// Cleartext password challenge.
	backend.Send(&pgproto3.AuthenticationCleartextPassword{})

	if err := backend.Flush(); err != nil {
		return err
	}

	if err := backend.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return err
	}

	msg, err := backend.Receive()
	if err != nil {
		return err
	}

	pw, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		return errUpstreamExpectedPwd
	}

	if pw.Password != testUpstreamPass {
		return &assertError{what: "password", got: pw.Password, want: testUpstreamPass}
	}

	// Auth success + full server greeting + ready.
	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "99.0"})
	backend.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 2}})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})

	if err := backend.Flush(); err != nil {
		return err
	}

	// Expect one query.
	queryMsg, err := backend.Receive()
	if err != nil {
		return err
	}

	if _, ok := queryMsg.(*pgproto3.Query); !ok {
		return errUpstreamExpectedQuery
	}

	backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})

	return backend.Flush()
}

var (
	errUpstreamExpectedStartup = errors.New("upstream: expected StartupMessage")
	errUpstreamExpectedPwd     = errors.New("upstream: expected PasswordMessage")
	errUpstreamExpectedQuery   = errors.New("upstream: expected Query")
)

type assertError struct {
	what, got, want string
}

func (a *assertError) Error() string {
	return "upstream: " + a.what + "=" + a.got + " want=" + a.want
}

func TestProxy_Serve_CancelRequest(t *testing.T) {
	p, md := newTestProxy(t)

	clientSide, proxyClientSide := net.Pipe()
	upstreamServerSide, upstreamClientSide := net.Pipe()
	md.setNextConn(upstreamClientSide)

	conn := newProxyConnFake(proxyClientSide)
	// A cancel needs no upstream credential, so it succeeds without auths.
	conn.claims.Resource.GatewayMetadata.Auths = nil

	want := &pgproto3.CancelRequest{ProcessID: 4242, SecretKey: []byte{0xde, 0xad, 0xbe, 0xef}}

	upstreamReceived := make(chan pgproto3.FrontendMessage, 1)

	go func() {
		defer upstreamServerSide.Close()

		msg, err := pgproto3.NewBackend(upstreamServerSide, upstreamServerSide).ReceiveStartupMessage()
		if err != nil {
			upstreamReceived <- nil

			return
		}

		upstreamReceived <- msg
	}()

	serveDone := make(chan error, 1)

	go func() { serveDone <- p.Serve(t.Context(), conn) }()

	sslReq, err := (&pgproto3.SSLRequest{}).Encode(nil)
	require.NoError(t, err)
	_, err = clientSide.Write(sslReq)
	require.NoError(t, err)

	reply := make([]byte, 1)
	_, err = clientSide.Read(reply)
	require.NoError(t, err)
	assert.Equal(t, byte('N'), reply[0])

	cancelReq, err := want.Encode(nil)
	require.NoError(t, err)
	_, err = clientSide.Write(cancelReq)
	require.NoError(t, err)

	select {
	case got := <-upstreamReceived:
		assert.Equal(t, want, got)
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive the cancel request")
	}

	select {
	case err := <-serveDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}

	_, err = clientSide.Read(reply)
	assert.ErrorIs(t, err, io.EOF, "downstream connection should be closed without a reply")
}

func TestProxy_Serve_ShuttingDown(t *testing.T) {
	p, _ := newTestProxy(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	p.Shutdown(ctx)

	clientEnd, _ := net.Pipe()
	defer clientEnd.Close()

	conn := newProxyConnFake(clientEnd)

	err := p.Serve(ctx, conn)
	require.ErrorIs(t, err, errShuttingDown)
}

func TestProxy_Start_AcceptError(t *testing.T) {
	p, _ := newTestProxy(t)

	listener := &mockListener{}
	listener.On("Accept").Return(nil, errors.New("boom"))

	done := make(chan struct{})

	go func() {
		defer close(done)

		_ = p.Start(t.Context(), listener)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Start did not return")
	}

	listener.AssertExpectations(t)
}

type mockListener struct {
	mock.Mock
}

func (m *mockListener) Accept() (net.Conn, error) {
	args := m.Called()

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(net.Conn), args.Error(1)
}

func (m *mockListener) Close() error   { return nil }
func (m *mockListener) Addr() net.Addr { return nil }
