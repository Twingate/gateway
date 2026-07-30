// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

func TestProxyConn_UpgradeToTLS_WebAppResourceMintedCert(t *testing.T) {
	cert, err := NewDynamicCert(config.TLSDynamicConfig{
		CA: config.TLSDynamicCAConfig{
			SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/ca/tls.crt", PrivateKeyFile: "../../test/data/ca/tls.key"},
		},
		Cert: config.TLSDynamicCertConfig{},
	}, zap.NewNop())
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(data.CACert)

	proxyConn := &ProxyConn{
		TLSConfig:         &tls.Config{},
		CertProvider:      cert,
		DownstreamAddress: "grafana.internal:443",
		Claims:            &token.GATClaims{Resource: token.Resource{Type: token.ResourceTypeWebApp}},
		Logger:            zap.NewNop(),
	}

	leaf, err := upgradeToTLSHandshake(t, proxyConn, &tls.Config{
		ServerName: "grafana.internal",
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"grafana.internal"}, leaf.DNSNames)
}

func TestProxyConn_UpgradeToTLS_IPResourceMintedCert(t *testing.T) {
	cert, err := NewDynamicCert(config.TLSDynamicConfig{
		CA: config.TLSDynamicCAConfig{
			SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/ca/tls.crt", PrivateKeyFile: "../../test/data/ca/tls.key"},
		},
		Cert: config.TLSDynamicCertConfig{},
	}, zap.NewNop())
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(data.CACert)

	proxyConn := &ProxyConn{
		TLSConfig:         &tls.Config{},
		CertProvider:      cert,
		DownstreamAddress: "10.0.0.5:443",
		Claims:            &token.GATClaims{Resource: token.Resource{Type: token.ResourceTypeWebApp}},
		Logger:            zap.NewNop(),
	}

	leaf, err := upgradeToTLSHandshake(t, proxyConn, &tls.Config{
		ServerName: "10.0.0.5",
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
	})
	require.NoError(t, err)

	require.Len(t, leaf.IPAddresses, 1)
	assert.True(t, leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")))
}

func TestProxyConn_UpgradeToTLS_StaticPinsStaticCert(t *testing.T) {
	serverTLSConfig, serverCert := staticServerTLSConfig(t)

	certReloader := NewCertReloader("../../test/data/proxy/tls.crt", "../../test/data/proxy/tls.key", zap.NewNop())
	certReloader.Run(t.Context())
	requireCertReloader(t, certReloader, serverCert)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(data.ProxyCert)

	proxyConn := &ProxyConn{
		TLSConfig:         serverTLSConfig,
		CertProvider:      certReloader,
		DownstreamAddress: "app.internal:443",
		Claims:            &token.GATClaims{Resource: token.Resource{Type: token.ResourceTypeWebApp}},
		Logger:            zap.NewNop(),
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
	cert, err := NewDynamicCert(config.TLSDynamicConfig{
		CA: config.TLSDynamicCAConfig{
			SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/ca/tls.crt", PrivateKeyFile: "../../test/data/ca/tls.key"},
		},
		Cert: config.TLSDynamicCertConfig{},
	}, zap.NewNop())
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(data.CACert)

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
		Conn:              conn,
		TLSConfig:         &tls.Config{},
		CertProvider:      cert,
		DownstreamAddress: "app.internal:443",
		Claims:            &token.GATClaims{Resource: token.Resource{Type: token.ResourceTypeWebApp}},
		Logger:            zap.NewNop(),
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
	cert, err := NewDynamicCert(config.TLSDynamicConfig{
		CA: config.TLSDynamicCAConfig{
			SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/ca/tls.crt", PrivateKeyFile: "../../test/data/ca/tls.key"},
		},
		Cert: config.TLSDynamicCertConfig{},
	}, zap.NewNop())
	require.NoError(t, err)

	// The client trusts a different CA, so it rejects the minted certificate
	// and the server-side handshake fails.
	wrongPool := x509.NewCertPool()
	wrongPool.AppendCertsFromPEM(data.ProxyCert)

	proxyConn := &ProxyConn{
		TLSConfig:         &tls.Config{},
		CertProvider:      cert,
		DownstreamAddress: "app.internal:443",
		Claims:            &token.GATClaims{Resource: token.Resource{Type: token.ResourceTypeWebApp}},
		Logger:            zap.NewNop(),
	}

	_, err = upgradeToTLSHandshake(t, proxyConn, &tls.Config{
		ServerName: "app.internal",
		RootCAs:    wrongPool,
		MinVersion: tls.VersionTLS13,
	})

	require.Error(t, err)
}

func TestProxyConn_UpgradeToTLS_MalformedDownstreamAddress(t *testing.T) {
	cert, err := NewDynamicCert(config.TLSDynamicConfig{
		CA: config.TLSDynamicCAConfig{
			SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/ca/tls.crt", PrivateKeyFile: "../../test/data/ca/tls.key"},
		},
		Cert: config.TLSDynamicCertConfig{},
	}, zap.NewNop())
	require.NoError(t, err)

	proxyConn := &ProxyConn{
		TLSConfig:         &tls.Config{},
		CertProvider:      cert,
		DownstreamAddress: "garbage",
		Claims:            &token.GATClaims{Resource: token.Resource{Type: token.ResourceTypeWebApp}},
		Logger:            zap.NewNop(),
	}

	_, err = upgradeToTLSHandshake(t, proxyConn, &tls.Config{
		ServerName: "garbage",
		MinVersion: tls.VersionTLS13,
	})

	require.Error(t, err)
	assert.ErrorContains(t, err, `failed to parse downstream address "garbage"`)
}

var errCertProviderFailed = errors.New("cert provider failed")

type failingCertProvider struct{}

func (failingCertProvider) Run(_ context.Context) {}

func (failingCertProvider) GetCertificateForHost(_ string) (*tls.Certificate, error) {
	return nil, errCertProviderFailed
}

func TestProxyConn_UpgradeToTLS_CertProviderError(t *testing.T) {
	proxyConn := &ProxyConn{
		TLSConfig:         &tls.Config{},
		CertProvider:      failingCertProvider{},
		DownstreamAddress: "app.internal:443",
		Claims:            &token.GATClaims{Resource: token.Resource{Type: token.ResourceTypeWebApp}},
		Logger:            zap.NewNop(),
	}

	_, err := upgradeToTLSHandshake(t, proxyConn, &tls.Config{
		ServerName: "app.internal",
		MinVersion: tls.VersionTLS13,
	})

	require.ErrorIs(t, err, errCertProviderFailed)
	assert.ErrorContains(t, err, `failed to get certificate for "app.internal"`)
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
