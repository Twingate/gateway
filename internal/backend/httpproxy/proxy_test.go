// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"gateway/internal/frontend"
	"gateway/internal/logging"
	"gateway/internal/metrics"
	"gateway/internal/token"
	"gateway/test/data"
)

var (
	tlsClaims = &token.GATClaims{
		User:     token.User{Username: "test@acme.com"},
		Resource: token.Resource{Type: token.ResourceTypeKubernetes, Address: "127.0.0.1"},
	}
	plaintextClaims = &token.GATClaims{
		User: token.User{Username: "test@acme.com"},
		Resource: token.Resource{
			Type:    token.ResourceTypeWebApp,
			Address: "127.0.0.1",
			GatewayMetadata: token.GatewayMetadata{
				Downstream: token.Downstream{TLSMode: token.TLSServerModeNone},
			},
		},
	}
)

type mockConnListener struct {
	net.Listener

	claims    *token.GATClaims
	tlsConfig *tls.Config
}

func (l *mockConnListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
	proxyConn := frontend.NewProxyConn(conn, l.tlsConfig, nil, zap.NewNop(), connMetrics)
	proxyConn.ID = "test-conn"
	proxyConn.RequestedHost = "127.0.0.1"
	proxyConn.UpstreamHost = "localhost"
	proxyConn.Claims = l.claims

	return proxyConn, nil
}

func TestProxyConnFromContext(t *testing.T) {
	t.Run("Returns ProxyConn from context", func(t *testing.T) {
		connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
		expected := frontend.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)

		ctx := context.WithValue(t.Context(), ConnContextKey{}, expected)

		actual := ProxyConnFromContext(ctx)
		assert.Equal(t, expected, actual)
	})

	t.Run("Panics when ProxyConn is not in context", func(t *testing.T) {
		assert.Panics(t, func() {
			ProxyConnFromContext(t.Context())
		})
	})
}

func TestProxy_ForwardRequest(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	proxy := NewProxy(Config{
		Metrics:      metrics.RegisterHTTPMetrics(prometheus.NewRegistry()),
		ResourceType: metrics.ResourceTypeKubernetes,
		Handler:      handler,
		Logger:       logging.NewNop(),
	})

	go func() {
		_ = proxy.Start(&mockConnListener{Listener: listener, claims: plaintextClaims})
	}()

	defer func() {
		_ = proxy.Shutdown(context.Background())
	}()

	resp, err := http.Get("http://" + listener.Addr().String() + "/test")
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "OK", string(body))
}

func TestProxy_ForwardRequest_HTTP2(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serverCert, err := tls.X509KeyPair(data.ProxyCert, data.ProxyKey)
	require.NoError(t, err)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13}

	proxy := NewProxy(Config{
		Metrics:      metrics.RegisterHTTPMetrics(prometheus.NewRegistry()),
		ResourceType: metrics.ResourceTypeWebApp,
		Handler:      handler,
		Logger:       logging.NewNop(),
	})

	go func() {
		_ = proxy.Start(&mockConnListener{Listener: listener, claims: tlsClaims, tlsConfig: tlsConfig})
	}()

	defer func() {
		_ = proxy.Shutdown(context.Background())
	}()

	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(data.ProxyCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS13},
			ForceAttemptHTTP2: true,
		},
	}

	resp, err := client.Get("https://" + listener.Addr().String() + "/test")
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "HTTP/2.0", resp.Proto)
	assert.Empty(t, tlsConfig.NextProtos, "the connection's TLS config is not modified")
}

func TestProxy_AuditRedirectedRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	core, logs := observer.New(zap.DebugLevel)

	proxy := NewProxy(Config{
		Metrics:      metrics.RegisterHTTPMetrics(prometheus.NewRegistry()),
		ResourceType: metrics.ResourceTypeKubernetes,
		Handler:      http.NotFoundHandler(),
		Logger:       logging.Logger{System: zap.NewNop(), Audit: zap.New(core), Session: zap.NewNop()},
	})

	go func() {
		_ = proxy.Start(&mockConnListener{Listener: listener, claims: plaintextClaims})
	}()

	defer func() {
		_ = proxy.Shutdown(context.Background())
	}()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get("http://" + listener.Addr().String() + "/test//path")
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	assert.Equal(t, "/test/path", resp.Header.Get("Location"))

	require.Len(t, logs.All(), 1)
	logContext := logs.All()[0].ContextMap()
	assert.Equal(t, "/test//path", logContext["url"])
	assert.Equal(t, http.StatusTemporaryRedirect, logContext["response"].(map[string]any)["status_code"])
}

func TestProxy_Start_UpgradesTLS(t *testing.T) {
	serverCert, err := tls.X509KeyPair(data.ProxyCert, data.ProxyKey)
	require.NoError(t, err)

	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(data.ProxyCert)

	tests := []struct {
		name    string
		claims  *token.GATClaims
		wantTLS bool
	}{
		{
			name:    "TLS when the GAT requires it",
			claims:  tlsClaims,
			wantTLS: true,
		},
		{
			name:    "plaintext when the GAT does not require TLS",
			claims:  plaintextClaims,
			wantTLS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)

			served := make(chan *http.Request, 1)
			handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				served <- r
			})

			proxy := NewProxy(Config{
				Metrics:      metrics.RegisterHTTPMetrics(prometheus.NewRegistry()),
				ResourceType: metrics.ResourceTypeKubernetes,
				Handler:      handler,
				Logger:       logging.NewNop(),
			})

			go func() {
				_ = proxy.Start(&mockConnListener{
					Listener:  listener,
					claims:    tt.claims,
					tlsConfig: &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13},
				})
			}()

			t.Cleanup(func() {
				_ = proxy.Shutdown(context.Background())
			})

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS13},
				},
			}

			scheme := "http"
			if tt.wantTLS {
				scheme = "https"
			}

			resp, err := client.Get(scheme + "://" + listener.Addr().String() + "/")
			require.NoError(t, err)

			defer resp.Body.Close()

			r := <-served
			assert.Equal(t, tt.wantTLS, r.TLS != nil)
			assert.NotPanics(t, func() {
				assert.Equal(t, "test-conn", ProxyConnFromContext(r.Context()).GetID())
			})
		})
	}
}

func TestProxy_Shutdown(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	proxy := NewProxy(Config{
		Metrics:      metrics.RegisterHTTPMetrics(prometheus.NewRegistry()),
		ResourceType: metrics.ResourceTypeKubernetes,
		Handler:      handler,
		Logger:       logging.NewNop(),
	})

	done := make(chan error, 1)

	go func() {
		done <- proxy.Start(&mockConnListener{Listener: listener, claims: plaintextClaims})
	}()

	err = proxy.Shutdown(context.Background())
	require.NoError(t, err)

	serveErr := <-done
	assert.ErrorIs(t, serveErr, http.ErrServerClosed)
}
