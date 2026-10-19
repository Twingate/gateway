// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"context"
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
)

type mockConnListener struct {
	net.Listener
}

func (l *mockConnListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
	proxyConn := frontend.NewProxyConn(conn, nil, nil, zap.NewNop(), connMetrics)
	proxyConn.ID = "test-conn"
	proxyConn.RequestedHost = "localhost"
	proxyConn.UpstreamHost = "localhost"
	proxyConn.Claims = &token.GATClaims{
		User:     token.User{Username: "test@acme.com"},
		Resource: token.Resource{Type: token.ResourceTypeKubernetes},
	}

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
		_ = proxy.Start(&mockConnListener{Listener: listener})
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
		_ = proxy.Start(&mockConnListener{Listener: listener})
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
		done <- proxy.Start(&mockConnListener{Listener: listener})
	}()

	err = proxy.Shutdown(context.Background())
	require.NoError(t, err)

	serveErr := <-done
	assert.ErrorIs(t, serveErr, http.ErrServerClosed)
}
