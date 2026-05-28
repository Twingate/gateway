// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/token"
)

type mockProxyConn struct {
	net.Conn

	transportProtocol TransportProtocol
	Claims            *token.GATClaims

	isClosed atomic.Bool

	isHealthz bool
}

func (m *mockProxyConn) Close() error {
	_ = m.Conn.Close()
	m.isClosed.Store(true)

	return nil
}

func (m *mockProxyConn) IsClosed() bool {
	return m.isClosed.Load()
}

func (m *mockProxyConn) TransportProtocol() TransportProtocol {
	return m.transportProtocol
}

func (m *mockProxyConn) GATClaims() *token.GATClaims {
	return m.Claims
}

func (m *mockProxyConn) GetID() string {
	return "mock"
}

func (m *mockProxyConn) GetAddress() string {
	return "mock"
}

func (m *mockProxyConn) GetToken() string {
	return ""
}

func (m *mockProxyConn) Authenticate() error {
	if m.isHealthz {
		// write health check response
		_, err := m.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		if err != nil {
			return err
		}

		return io.EOF
	}

	return nil
}

func (m *mockProxyConn) ShouldUpgradeTLS() bool {
	return m.TransportProtocol() == TransportTLS && m.GATClaims().Resource.Type != token.ResourceTypeWebApp
}

func (m *mockProxyConn) UpgradeToTLS() error {
	return nil
}

func createMockListener(t *testing.T) (net.Listener, string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := listener.Addr().String()

	return listener, addr
}

var listenerClaims = &token.GATClaims{
	RegisteredClaims: jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	},
	User: token.User{
		ID:       "user-1",
		Username: "user@acme.com",
		Groups:   []string{"Everyone", "Engineering"},
	},
	Resource: token.Resource{ID: "resource-1", Type: token.ResourceTypeKubernetes, Address: "https://api.acme.com"},
}

type testListenerFixtures struct {
	listener    *Listener
	tcpListener net.Listener
	httpChannel chan Conn
	sshChannel  chan Conn
	addr        string
}

func createTestListenerWithChannels(t *testing.T) *testListenerFixtures {
	t.Helper()

	tcpListener, addr := createMockListener(t)

	// Create channels for testing
	httpChannel := make(chan Conn, 1)
	sshChannel := make(chan Conn, 1)
	channels := map[TransportProtocol]chan<- Conn{
		TransportTLS: httpChannel,
		TransportSSH: sshChannel,
	}

	registry := prometheus.NewRegistry()
	logger := zap.NewNop()
	certReloader := NewCertReloader("../../test/data/proxy/tls.crt", "../../test/data/proxy/tls.key", logger)

	// Create listener with minimal config (we'll override the factory)
	listener := &Listener{
		channels:     channels,
		logger:       logger,
		metrics:      CreateProxyConnMetrics(registry),
		certReloader: certReloader,
	}

	return &testListenerFixtures{
		listener:    listener,
		tcpListener: tcpListener,
		httpChannel: httpChannel,
		sshChannel:  sshChannel,
		addr:        addr,
	}
}

func TestListener_Serve_HTTPS(t *testing.T) {
	fixtures := createTestListenerWithChannels(t)

	fixtures.listener.proxyConnFactory = func(conn net.Conn, _ *tls.Config, _ Validator, _ *zap.Logger) Conn {
		return &mockProxyConn{
			Conn:              conn,
			transportProtocol: TransportTLS,
			Claims:            listenerClaims,
		}
	}

	go func() {
		_ = fixtures.listener.Serve(t.Context(), fixtures.tcpListener)
	}()

	// Open TCP connection to the mock listener
	go func() {
		_, err := net.Dial("tcp", fixtures.addr)
		assert.NoError(t, err)
	}()

	// Listen for SSH connections, we should not receive any
	waitGroup := sync.WaitGroup{}

	waitGroup.Go(func() {
		select {
		case conn, ok := <-fixtures.sshChannel:
			if ok {
				t.Errorf("unexpected SSH connection: %v", conn)
			}
		case <-time.After(100 * time.Millisecond):
			// Expected - no SSH connection
		}
	})

	// Accept the HTTP connection from channel
	select {
	case conn := <-fixtures.httpChannel:
		require.False(t, conn.(*mockProxyConn).IsClosed())
		require.Equal(t, TransportTLS, conn.TransportProtocol())
		require.Equal(t, listenerClaims, conn.GATClaims())
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for HTTP connection")
	}

	// Close the listener
	_ = fixtures.tcpListener.Close()

	// Wait for the SSH listener goroutine
	waitGroup.Wait()
}

func TestListener_Serve_SSH(t *testing.T) {
	fixtures := createTestListenerWithChannels(t)

	fixtures.listener.proxyConnFactory = func(conn net.Conn, _ *tls.Config, _ Validator, _ *zap.Logger) Conn {
		return &mockProxyConn{
			Conn:              conn,
			transportProtocol: TransportSSH,
			Claims:            listenerClaims,
		}
	}

	go func() {
		_ = fixtures.listener.Serve(t.Context(), fixtures.tcpListener)
	}()

	// Open TCP connection to the mock listener
	go func() {
		_, err := net.Dial("tcp", fixtures.addr)
		assert.NoError(t, err)
	}()

	// Listen for HTTP connections, we should not receive any
	waitGroup := sync.WaitGroup{}

	waitGroup.Go(func() {
		select {
		case conn, ok := <-fixtures.httpChannel:
			if ok {
				t.Errorf("unexpected HTTP connection: %v", conn)
			}
		case <-time.After(100 * time.Millisecond):
			// Expected - no HTTP connection
		}
	})

	// Accept the SSH connection from channel
	select {
	case conn := <-fixtures.sshChannel:
		require.False(t, conn.(*mockProxyConn).IsClosed())
		require.Equal(t, TransportSSH, conn.TransportProtocol())
		require.Equal(t, listenerClaims, conn.GATClaims())
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for SSH connection")
	}

	// Close the listener
	_ = fixtures.tcpListener.Close()

	// Wait for the HTTP listener goroutine
	waitGroup.Wait()
}

func TestListener_Serve_Healthz(t *testing.T) {
	fixtures := createTestListenerWithChannels(t)

	fixtures.listener.proxyConnFactory = func(conn net.Conn, _ *tls.Config, _ Validator, _ *zap.Logger) Conn {
		return &mockProxyConn{
			Conn:      conn,
			isHealthz: true,
		}
	}

	go func() {
		_ = fixtures.listener.Serve(t.Context(), fixtures.tcpListener)
	}()

	// Open TCP connection to the mock listener
	done := make(chan struct{})

	go func() {
		conn, err := net.Dial("tcp", fixtures.addr)
		assert.NoError(t, err)
		// Read the health check response
		buf := bufio.NewReader(conn)
		resp, err := buf.ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 200 OK\r\n", resp)
		// Continue reading, should be closed with EOF
		_, err = conn.Read(make([]byte, 1))
		assert.ErrorIs(t, err, io.EOF)

		done <- struct{}{}
	}()

	// To wait for listener checks
	waitGroup := sync.WaitGroup{}
	waitGroup.Add(2)

	// We should not receive any HTTP connections
	go func() {
		defer waitGroup.Done()

		select {
		case conn, ok := <-fixtures.httpChannel:
			if ok {
				t.Errorf("unexpected HTTP connection: %v", conn)
			}
		case <-time.After(100 * time.Millisecond):
			// Expected - no HTTP connection
		}
	}()

	// We should not receive any SSH connections
	go func() {
		defer waitGroup.Done()

		select {
		case conn, ok := <-fixtures.sshChannel:
			if ok {
				t.Errorf("unexpected SSH connection: %v", conn)
			}
		case <-time.After(100 * time.Millisecond):
			// Expected - no SSH connection
		}
	}()

	// Wait for health check connection to finish
	<-done

	// Close the listener
	_ = fixtures.tcpListener.Close()

	// Now wait for all listener checks to complete
	waitGroup.Wait()
}

func TestListener_UnsupportedTransport(t *testing.T) {
	tcpListener, addr := createMockListener(t)

	// Create channels but omit one transport type
	httpChannel := make(chan Conn, 1)
	channels := map[TransportProtocol]chan<- Conn{
		TransportTLS: httpChannel,
		// SSH not included - unsupported
	}

	registry := prometheus.NewRegistry()
	logger := zap.NewNop()
	certReloader := NewCertReloader("../../test/data/proxy/tls.crt", "../../test/data/proxy/tls.key", logger)

	listener := &Listener{
		channels:     channels,
		logger:       logger,
		metrics:      CreateProxyConnMetrics(registry),
		certReloader: certReloader,
	}

	// Use a channel to safely pass the connection from the factory
	connCreated := make(chan *mockProxyConn, 1)
	listener.proxyConnFactory = func(conn net.Conn, _ *tls.Config, _ Validator, _ *zap.Logger) Conn {
		mockConn := &mockProxyConn{
			Conn:              conn,
			transportProtocol: TransportSSH, // This transport is not supported
			Claims:            listenerClaims,
		}
		connCreated <- mockConn

		return mockConn
	}

	go func() {
		_ = listener.Serve(t.Context(), tcpListener)
	}()

	// Open TCP connection
	go func() {
		_, err := net.Dial("tcp", addr)
		assert.NoError(t, err)
	}()

	// Wait for connection to be created
	closedConn := <-connCreated

	// Connection should be closed (unsupported transport)
	require.Eventually(t, closedConn.IsClosed, time.Second, 10*time.Millisecond)

	// Channel should be empty (connection was not routed)
	require.Empty(t, httpChannel)

	// Close the listener
	_ = tcpListener.Close()
}

func TestListener_Serve_GracefulShutdown(t *testing.T) {
	tcpListener, addr := createMockListener(t)

	// Use unbuffered channel so the goroutine inside Serve blocks on send
	httpChannel := make(chan Conn)
	channels := map[TransportProtocol]chan<- Conn{
		TransportTLS: httpChannel,
	}

	logger := zap.NewNop()

	listener := &Listener{
		channels:     channels,
		logger:       logger,
		metrics:      CreateProxyConnMetrics(prometheus.NewRegistry()),
		certReloader: NewCertReloader("../../test/data/proxy/tls.crt", "../../test/data/proxy/tls.key", logger),
	}

	listener.proxyConnFactory = func(conn net.Conn, _ *tls.Config, _ Validator, _ *zap.Logger) Conn {
		return &mockProxyConn{
			Conn:              conn,
			transportProtocol: TransportTLS,
			Claims:            listenerClaims,
		}
	}

	serveDone := make(chan struct{})

	go func() {
		_ = listener.Serve(t.Context(), tcpListener)

		close(serveDone)
	}()

	// Open TCP connection then close the listener
	go func() {
		_, err := net.Dial("tcp", addr)
		assert.NoError(t, err)
	}()

	time.Sleep(50 * time.Millisecond)

	_ = tcpListener.Close()

	// Serve should be blocked: the connection goroutine is waiting on unbuffered channel send
	select {
	case <-serveDone:
		t.Fatal("Serve returned before connection goroutine completed")
	case <-time.After(100 * time.Millisecond):
		// Expected - Serve is waiting for the goroutine
	}

	// Drain channel to unblock the goroutine
	conn := <-httpChannel
	require.NotNil(t, conn)

	// Serve should now return and channels should be closed
	select {
	case <-serveDone:
		_, ok := <-httpChannel
		require.False(t, ok, "channel should be closed after Serve returns")
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Serve to return")
	}
}

func TestProtocolListener(t *testing.T) {
	_, addr := createMockListener(t)
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	require.NoError(t, err)

	// Create a ProtocolListener
	ch := make(chan Conn, 1)
	protocolListener := NewProtocolListener(ch, tcpAddr)

	// Check that Addr() returns the correct address
	assert.Equal(t, addr, protocolListener.Addr().String())

	// Send a mock connection
	mockConn := &mockProxyConn{
		transportProtocol: TransportTLS,
		Claims:            listenerClaims,
	}
	ch <- mockConn

	// Accept should return the connection
	conn, err := protocolListener.Accept()
	require.NoError(t, err)
	require.Equal(t, mockConn, conn)

	// Close the listener
	err = protocolListener.Close()
	require.NoError(t, err)

	// Accept should return error after close
	conn, err = protocolListener.Accept()
	assert.Nil(t, conn)
	require.ErrorIs(t, err, net.ErrClosed)

	// Close again should not panic
	err = protocolListener.Close()
	require.NoError(t, err)
}

func TestProtocolListener_ClosedChannel(t *testing.T) {
	_, addr := createMockListener(t)
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	require.NoError(t, err)

	// Create a ProtocolListener
	ch := make(chan Conn)
	protocolListener := NewProtocolListener(ch, tcpAddr)

	// Close the channel
	close(ch)

	// Accept should return error when channel is closed
	conn, err := protocolListener.Accept()
	assert.Nil(t, conn)
	require.ErrorIs(t, err, net.ErrClosed)
}
