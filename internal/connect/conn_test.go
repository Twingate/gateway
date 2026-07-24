// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"gateway/internal/config"
	"gateway/internal/token"
	"gateway/test/data"
)

type mockConn struct {
	net.Conn

	isClosed atomic.Bool
}

func (m *mockConn) Close() error {
	m.isClosed.Store(true)

	return nil
}

func (m *mockConn) IsClosed() bool {
	return m.isClosed.Load()
}

func TestProxyConn_setConnectInfo(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := &mockConn{}
		claims := &token.GATClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		}
		connID := "conn-id-1"

		metrics := CreateProxyConnMetrics(prometheus.NewRegistry())
		proxyConn := &ProxyConn{
			Conn:    conn,
			tracker: NewProxyConnMetricsTracker(ConnCategoryUnknown, metrics),
		}

		func() {
			// `setConnectInfo` should only be called after acquiring the lock. This is needed
			// because the timer is started in a separate goroutine.
			proxyConn.Mu.Lock()
			defer proxyConn.Mu.Unlock()

			proxyConn.setConnectInfo(Info{
				Claims: claims,
				ConnID: connID,
			})
		}()

		assert.Equal(t, connID, proxyConn.ID)
		assert.Equal(t, claims, proxyConn.Claims)

		// Wait for expiry timer to happen, the connection should be closed
		time.Sleep(1 * time.Hour)
		synctest.Wait()
		assert.True(t, conn.IsClosed())
	})
}

func TestProxyConn_Close(t *testing.T) {
	conn := &mockConn{}
	timer := time.NewTimer(0 * time.Millisecond)
	metrics := CreateProxyConnMetrics(prometheus.NewRegistry())
	proxyConn := &ProxyConn{
		Conn:    conn,
		Timer:   timer,
		tracker: NewProxyConnMetricsTracker(ConnCategoryUnknown, metrics),
	}

	_ = proxyConn.Close()

	assert.True(t, conn.IsClosed())

	// Verify that the timer was stopped
	select {
	case <-timer.C:
		assert.Fail(t, "Timer should have been stopped")
	default:
	}

	// Ensure metrics are only measured once
	_ = proxyConn.Close()

	count := promtestutil.ToFloat64(metrics.connTotal)
	assert.Equal(t, 1, int(count))
}

var errValidation = &HTTPError{
	Code:    http.StatusProxyAuthRequired,
	Message: "failed to validate token",
}

type mockValidator struct {
	shouldFail bool
	ProxyAuth  string
	TokenSig   string
	ConnID     string
}

var claims = &token.GATClaims{
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

func (m *mockValidator) ParseConnect(req *http.Request, _ []byte) (connectInfo Info, err error) {
	if m.shouldFail {
		return Info{
			Claims: nil,
			ConnID: "",
		}, errValidation
	}

	m.ProxyAuth = req.Header.Get(AuthHeaderKey)
	m.TokenSig = req.Header.Get(AuthSignatureHeaderKey)
	m.ConnID = req.Header.Get(ConnIDHeaderKey)

	return Info{Claims: claims, ConnID: m.ConnID}, nil
}

func startMockListener(t *testing.T) (net.Listener, string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := listener.Addr().String()

	return listener, addr
}

func TestProxyConn_Authenticate_BadRequest(t *testing.T) {
	listener, addr := startMockListener(t)

	// Client TLS config
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(data.ProxyCert)
	clientTLSConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS13,
	}

	done := make(chan struct{})

	// Downstream Client logic on separate goroutine
	go func() {
		// Open TCP connection to the mock listener
		conn, err := net.Dial("tcp", addr)
		assert.NoError(t, err)

		defer conn.Close()

		// Establish TLS (as downstream proxy)
		proxyTLSConn := tls.Client(conn, clientTLSConfig)
		if err := proxyTLSConn.Handshake(); err != nil {
			done <- struct{}{}

			return
		}

		// Send a malformed request
		_, err = fmt.Fprint(proxyTLSConn, "invalid-request\r\n\r\n")
		assert.NoError(t, err)

		resp, err := bufio.NewReader(proxyTLSConn).ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 400 Bad Request\r\n", resp)

		done <- struct{}{}
	}()

	// Accept the incoming connection from the downstream client
	conn, _ := listener.Accept()

	// Server TLS config
	serverCert, err := tls.X509KeyPair(data.ProxyCert, data.ProxyKey)
	require.NoError(t, err)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}

	// Mock CONNECT validator
	mockValidator := &mockValidator{
		shouldFail: false,
	}

	// Create the ProxyConn from the accepted connection
	metrics := CreateProxyConnMetrics(prometheus.NewRegistry())

	proxyConn := &ProxyConn{
		Conn:             conn,
		TLSConfig:        serverTLSConfig,
		ConnectValidator: mockValidator,
		Logger:           zap.NewNop(),
		tracker:          NewProxyConnMetricsTracker(ConnCategoryUnknown, metrics),
	}
	defer proxyConn.Close()

	// Perform connection auth logic
	if err := proxyConn.Authenticate(); err != nil {
		assert.ErrorContains(t, err, "malformed HTTP request \"invalid-request\"")
	}

	<-done
}

func TestProxyConn_Authenticate_HealthCheck(t *testing.T) {
	listener, addr := startMockListener(t)

	// Client TLS config
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(data.ProxyCert)
	clientTLSConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS13,
	}

	done := make(chan struct{})

	// Downstream Client logic on separate goroutine
	go func() {
		// Open TCP connection to the mock listener
		conn, err := net.Dial("tcp", addr)
		assert.NoError(t, err)

		defer conn.Close()

		// Establish TLS (as downstream proxy)
		proxyTLSConn := tls.Client(conn, clientTLSConfig)
		if err := proxyTLSConn.Handshake(); err != nil {
			done <- struct{}{}

			return
		}

		// Send a healthcheck request
		_, err = fmt.Fprint(proxyTLSConn, "GET /healthz HTTP/1.1\r\n\r\n")
		assert.NoError(t, err)

		buf := bufio.NewReader(proxyTLSConn)
		resp, err := buf.ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 200 OK\r\n", resp)
		resp, err = buf.ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "Content-Length: 0\r\n", resp)
		resp, err = buf.ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "Connection: close\r\n", resp)

		done <- struct{}{}
	}()

	// Accept the incoming connection from the downstream client
	conn, _ := listener.Accept()

	// Server TLS config
	serverCert, err := tls.X509KeyPair(data.ProxyCert, data.ProxyKey)
	require.NoError(t, err)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}

	// Mock CONNECT validator
	mockValidator := &mockValidator{
		shouldFail: false,
	}

	// Create the ProxyConn from the accepted connection
	metrics := CreateProxyConnMetrics(prometheus.NewRegistry())

	proxyConn := &ProxyConn{
		Conn:             conn,
		TLSConfig:        serverTLSConfig,
		ConnectValidator: mockValidator,
		Logger:           zap.NewNop(),
		tracker:          NewProxyConnMetricsTracker(ConnCategoryUnknown, metrics),
	}
	defer proxyConn.Close()

	// Perform connection auth logic
	assert.ErrorIs(t, proxyConn.Authenticate(), io.EOF)

	<-done
}

func TestProxyConn_Authenticate_ValidConnectRequest(t *testing.T) {
	listener, addr := startMockListener(t)

	// Client TLS config
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(data.ProxyCert)
	clientTLSConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS13,
	}

	done := make(chan struct{})

	// Downstream Client logic on separate goroutine
	go func() {
		// Open TCP connection to the mock listener
		conn, err := net.Dial("tcp", addr)
		assert.NoError(t, err)

		defer conn.Close()

		// Establish TLS (as downstream proxy)
		proxyTLSConn := tls.Client(conn, clientTLSConfig)
		if err := proxyTLSConn.Handshake(); err != nil {
			done <- struct{}{}

			return
		}

		// Send a valid CONNECT request
		_, err = fmt.Fprintf(proxyTLSConn, "CONNECT example.com:443 HTTP/1.1\r\n%s: gat_token\r\n%s: auth_sig\r\n%s: conn-id-1\r\n\r\n",
			AuthHeaderKey, AuthSignatureHeaderKey, ConnIDHeaderKey)
		assert.NoError(t, err)

		// Expect 200 Connection Established back
		resp, err := bufio.NewReader(proxyTLSConn).ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 200 OK\r\n", resp)

		done <- struct{}{}
	}()

	// Accept the incoming connection from the downstream client
	conn, _ := listener.Accept()

	// Server TLS config
	serverCert, err := tls.X509KeyPair(data.ProxyCert, data.ProxyKey)
	require.NoError(t, err)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}

	// Mock CONNECT validator
	mockValidator := &mockValidator{
		shouldFail: false,
	}

	// Create the ProxyConn from the accepted connection
	metrics := CreateProxyConnMetrics(prometheus.NewRegistry())

	proxyConn := &ProxyConn{
		Conn:             conn,
		TLSConfig:        serverTLSConfig,
		ConnectValidator: mockValidator,
		Logger:           zap.NewNop(),
		tracker:          NewProxyConnMetricsTracker(ConnCategoryUnknown, metrics),
	}
	defer proxyConn.Close()

	// Perform connection auth logic
	require.NoError(t, proxyConn.Authenticate())
	assert.Equal(t, claims, proxyConn.Claims)

	<-done
}

func TestProxyConn_Authenticate_FailedValidation(t *testing.T) {
	listener, addr := startMockListener(t)

	// Client TLS config
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(data.ProxyCert)
	clientTLSConfig := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS13,
	}

	done := make(chan struct{})

	// Downstream Client logic on separate goroutine
	go func() {
		// Open TCP connection to the mock listener
		conn, err := net.Dial("tcp", addr)
		assert.NoError(t, err)

		defer conn.Close()

		// Establish TLS (as downstream proxy)
		proxyTLSConn := tls.Client(conn, clientTLSConfig)
		if err := proxyTLSConn.Handshake(); err != nil {
			done <- struct{}{}

			return
		}

		// Send an invalid CONNECT request
		_, err = fmt.Fprintf(proxyTLSConn, "CONNECT example.com:443 HTTP/1.1\r\n%s: bad_token\r\n%s: auth_sig\r\n%s: conn-id-1\r\n\r\n",
			AuthHeaderKey, AuthSignatureHeaderKey, ConnIDHeaderKey)
		assert.NoError(t, err)

		resp, err := bufio.NewReader(proxyTLSConn).ReadString('\n')
		assert.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 407 Proxy Authentication Required\r\n", resp)

		done <- struct{}{}
	}()

	// Accept the incoming connection from the downstream client
	conn, _ := listener.Accept()

	// Server TLS config
	serverCert, err := tls.X509KeyPair(data.ProxyCert, data.ProxyKey)
	require.NoError(t, err)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}

	// Mock CONNECT validator
	mockValidator := &mockValidator{
		shouldFail: true,
	}

	// Create the ProxyConn from the accepted connection
	metrics := CreateProxyConnMetrics(prometheus.NewRegistry())

	proxyConn := &ProxyConn{
		Conn:             conn,
		TLSConfig:        serverTLSConfig,
		ConnectValidator: mockValidator,
		Logger:           zap.NewNop(),
		tracker:          NewProxyConnMetricsTracker(ConnCategoryUnknown, metrics),
	}
	defer proxyConn.Close()

	// Perform connection auth logic
	require.ErrorIs(t, proxyConn.Authenticate(), errValidation)
	assert.Nil(t, proxyConn.Claims)

	<-done
}

// upgradeToTLSHandshake runs proxyConn.UpgradeToTLS against a TLS client
// connected over TCP and returns the leaf certificate the client saw.
func upgradeToTLSHandshake(t *testing.T, proxyConn *ProxyConn, clientTLSConfig *tls.Config) (*x509.Certificate, error) {
	t.Helper()

	listener, addr := startMockListener(t)
	defer listener.Close()

	type clientResult struct {
		leaf *x509.Certificate
		err  error
	}

	clientCh := make(chan clientResult, 1)

	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			clientCh <- clientResult{nil, err}

			return
		}

		defer conn.Close()

		tlsConn := tls.Client(conn, clientTLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			clientCh <- clientResult{nil, err}

			return
		}

		clientCh <- clientResult{tlsConn.ConnectionState().PeerCertificates[0], nil}
	}()

	conn, err := listener.Accept()
	require.NoError(t, err)

	proxyConn.Conn = conn

	serverErr := proxyConn.UpgradeToTLS()
	if serverErr != nil {
		_ = conn.Close()

		<-clientCh

		return nil, serverErr
	}

	result := <-clientCh
	require.NoError(t, result.err)

	return result.leaf, nil
}

func staticServerTLSConfig(t *testing.T) (*tls.Config, tls.Certificate) {
	t.Helper()

	serverCert, err := tls.X509KeyPair(data.ProxyCert, data.ProxyKey)
	require.NoError(t, err)

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}, serverCert
}

func TestProxyConn_UpgradeToTLS_WebAppMintedCert(t *testing.T) {
	cert, caPool := newTestCert(t, config.TLSDynamicCertConfig{})
	serverTLSConfig, _ := staticServerTLSConfig(t)

	proxyConn := &ProxyConn{
		TLSConfig:      serverTLSConfig,
		Cert:           cert,
		DownstreamHost: "app.internal",
		Claims:         &token.GATClaims{Resource: token.Resource{Type: token.ResourceTypeWebApp}},
		Logger:         zap.NewNop(),
	}

	leaf, err := upgradeToTLSHandshake(t, proxyConn, &tls.Config{
		ServerName: "app.internal",
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"app.internal"}, leaf.DNSNames)
}

func TestProxyConn_UpgradeToTLS_KubernetesMintedCert(t *testing.T) {
	cert, caPool := newTestCert(t, config.TLSDynamicCertConfig{})
	serverTLSConfig, _ := staticServerTLSConfig(t)

	proxyConn := &ProxyConn{
		TLSConfig:      serverTLSConfig,
		Cert:           cert,
		DownstreamHost: "k8s.internal",
		Claims:         &token.GATClaims{Resource: token.Resource{Type: token.ResourceTypeKubernetes}},
		Logger:         zap.NewNop(),
	}

	leaf, err := upgradeToTLSHandshake(t, proxyConn, &tls.Config{
		ServerName: "k8s.internal",
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"k8s.internal"}, leaf.DNSNames)
}

func TestProxyConn_UpgradeToTLS_NoDynamicKeepsStaticCert(t *testing.T) {
	serverTLSConfig, serverCert := staticServerTLSConfig(t)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(data.ProxyCert)

	proxyConn := &ProxyConn{
		TLSConfig:      serverTLSConfig,
		DownstreamHost: "app.internal",
		Claims:         &token.GATClaims{Resource: token.Resource{Type: token.ResourceTypeWebApp}},
		Logger:         zap.NewNop(),
	}

	leaf, err := upgradeToTLSHandshake(t, proxyConn, &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS13,
	})
	require.NoError(t, err)

	assert.Equal(t, serverCert.Certificate[0], leaf.Raw)
}

func TestProxyConn_UpgradeToTLS_TerminatesTLSAtGateway(t *testing.T) {
	cert, caPool := newTestCert(t, config.TLSDynamicCertConfig{})
	serverTLSConfig, _ := staticServerTLSConfig(t)

	listener, addr := startMockListener(t)
	defer listener.Close()

	const request = "GET / HTTP/1.1\r\n\r\n"

	done := make(chan struct{})

	go func() {
		defer close(done)

		conn, err := net.Dial("tcp", addr)
		assert.NoError(t, err)

		defer conn.Close()

		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: "app.internal",
			RootCAs:    caPool,
			MinVersion: tls.VersionTLS13,
		})
		assert.NoError(t, tlsConn.Handshake())

		_, err = tlsConn.Write([]byte(request))
		assert.NoError(t, err)
	}()

	conn, err := listener.Accept()
	require.NoError(t, err)

	proxyConn := &ProxyConn{
		Conn:           conn,
		TLSConfig:      serverTLSConfig,
		Cert:           cert,
		DownstreamHost: "app.internal",
		Claims:         &token.GATClaims{Resource: token.Resource{Type: token.ResourceTypeWebApp}},
		Logger:         zap.NewNop(),
	}

	require.NoError(t, proxyConn.UpgradeToTLS())

	// The gateway reads the decrypted plaintext through the upgraded connection.
	buf := make([]byte, len(request))
	_, err = io.ReadFull(proxyConn, buf)
	require.NoError(t, err)
	assert.Equal(t, request, string(buf))

	<-done
}

func TestProxyConn_UpgradeToTLS_HandshakeError(t *testing.T) {
	cert, _ := newTestCert(t, config.TLSDynamicCertConfig{})
	serverTLSConfig, _ := staticServerTLSConfig(t)

	// The client trusts a different CA, so it rejects the minted certificate
	// and the server-side handshake fails.
	wrongPool := x509.NewCertPool()
	wrongPool.AppendCertsFromPEM(data.ProxyCert)

	proxyConn := &ProxyConn{
		TLSConfig:      serverTLSConfig,
		Cert:           cert,
		DownstreamHost: "app.internal",
		Claims:         &token.GATClaims{Resource: token.Resource{Type: token.ResourceTypeWebApp}},
		Logger:         zap.NewNop(),
	}

	_, err := upgradeToTLSHandshake(t, proxyConn, &tls.Config{
		ServerName: "app.internal",
		RootCAs:    wrongPool,
		MinVersion: tls.VersionTLS13,
	})

	require.Error(t, err)
}

func TestProxyConn_UpgradeToTLS_MintError(t *testing.T) {
	cert, caPool := newTestCert(t, config.TLSDynamicCertConfig{KeyType: "ed25519"})
	serverTLSConfig, _ := staticServerTLSConfig(t)

	proxyConn := &ProxyConn{
		TLSConfig:      serverTLSConfig,
		Cert:           cert,
		DownstreamHost: "app.internal",
		Claims:         &token.GATClaims{Resource: token.Resource{Type: token.ResourceTypeWebApp}},
		Logger:         zap.NewNop(),
	}

	_, err := upgradeToTLSHandshake(t, proxyConn, &tls.Config{
		ServerName: "app.internal",
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, errUnsupportedKeyType)
}

func TestIsHealthCheckRequest(t *testing.T) {
	testCases := []struct {
		name           string
		request        *http.Request
		expectedResult bool
	}{
		{
			name:           "Healthcheck request",
			request:        httptest.NewRequest(http.MethodGet, healthCheckPath, nil),
			expectedResult: true,
		},
		{
			name:           "POST request to healthcheck path",
			request:        httptest.NewRequest(http.MethodPost, healthCheckPath, nil),
			expectedResult: false,
		},
		{
			name:           "Proxy request",
			request:        httptest.NewRequest(http.MethodConnect, "", nil),
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedResult, isHealthCheckRequest(tc.request))
		})
	}
}
