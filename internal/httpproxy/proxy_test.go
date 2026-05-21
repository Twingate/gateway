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
	proxyConn.Claims = &token.GATClaims{User: token.User{Username: "test@acme.com"}}

	return proxyConn, nil
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
		Handler:  handler,
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
		Handler:  handler,
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
