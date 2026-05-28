// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/connect"
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

	connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
	proxyConn := connect.NewProxyConn(conn, nil, nil, zap.NewNop(), connMetrics)
	proxyConn.ID = "test-conn"
	proxyConn.Address = "localhost"
	proxyConn.Claims = &token.GATClaims{
		User:     token.User{Username: "test@acme.com"},
		Resource: token.Resource{Type: token.ResourceTypeKubernetes},
	}

	return proxyConn, nil
}

func TestProxyConnFromContext(t *testing.T) {
	t.Run("Returns ProxyConn from context", func(t *testing.T) {
		connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
		expected := connect.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)

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

func TestResourceRouter_DispatchesToCorrectHandler(t *testing.T) {
	var handledBy = ""

	handlers := map[string]http.Handler{
		token.ResourceTypeKubernetes: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handledBy = "kubernetes"

			w.WriteHeader(http.StatusOK)
		}),
		token.ResourceTypeSSH: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handledBy = "ssh"

			w.WriteHeader(http.StatusOK)
		}),
	}

	connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
	proxyConn := connect.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	proxyConn.Claims = &token.GATClaims{
		Resource: token.Resource{Type: token.ResourceTypeKubernetes},
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), ConnContextKey{}, proxyConn)
	req = req.WithContext(ctx)

	router := newResourceRouter(handlers, zap.NewNop())
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "kubernetes", handledBy)
}

func TestResourceRouter_UnknownResource(t *testing.T) {
	handlers := map[string]http.Handler{
		token.ResourceTypeKubernetes: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}

	connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
	proxyConn := connect.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	proxyConn.Claims = &token.GATClaims{
		Resource: token.Resource{Type: "unknown"},
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), ConnContextKey{}, proxyConn)
	req = req.WithContext(ctx)

	router := newResourceRouter(handlers, zap.NewNop())
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func TestProxy_ForwardRequest(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	proxy := NewProxy(Config{
		Registry: prometheus.NewRegistry(),
		Handlers: map[string]http.Handler{token.ResourceTypeKubernetes: handler},
		Logger:   zap.NewNop(),
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

func TestProxy_Shutdown(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	proxy := NewProxy(Config{
		Handlers: map[string]http.Handler{token.ResourceTypeKubernetes: handler},
		Registry: prometheus.NewRegistry(),
		Logger:   zap.NewNop(),
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
