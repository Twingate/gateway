// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httphandler

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/connect"
	"gateway/internal/token"
	"gateway/test/data"
)

func TestProxy_ForwardRequest(t *testing.T) {
	// Create mock upstream API server
	apiServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify proxy sets correct impersonation headers
		assert.Equal(t, "user@acme.com", r.Header.Get("Impersonate-User"))
		assert.Equal(t, []string{"Everyone", "Engineering"}, r.Header.Values("Impersonate-Group"))
		// Verify proxy sets correct authorization token
		assert.Equal(t, "Bearer mock-token", r.Header.Get("Authorization"))
		// Send response
		_, err := io.WriteString(w, "Upstream API Server Response!")
		assert.NoError(t, err)
	}))

	// Configure TLS for the mock API server
	serverCert, err := tls.X509KeyPair(data.ServerCert, data.ServerKey)
	require.NoError(t, err)

	apiServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}

	apiServer.StartTLS()
	defer apiServer.Close()

	apiServerAddress := strings.TrimPrefix(apiServer.URL, "https://")

	// Create channel and ProtocolListener (simulating connect package output)
	ch := make(chan connect.Conn)

	t.Cleanup(func() {
		close(ch)
	})

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	protocolListener := connect.NewProtocolListener(ch, addr)

	// Create HTTP proxy
	cfg := Config{
		registry:    prometheus.NewRegistry(),
		caFile:      "../../test/data/api_server/tls.crt",
		bearerToken: "mock-token",
		logger:      zap.NewNop(),
	}

	httpProxy, err := NewProxy(cfg)
	require.NoError(t, err)

	go func() {
		_ = httpProxy.Start(protocolListener)
	}()

	// Create a pipe for communication (client <-> proxy)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// Create ProxyConn with Claims (simulating authenticated connection from connect package)
	claims := &token.GATClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
		User: token.User{
			ID:       "user-1",
			Username: "user@acme.com",
			Groups:   []string{"Everyone", "Engineering"},
		},
		Resource: token.Resource{ID: "resource-1", Type: token.ResourceTypeKubernetes, Address: apiServerAddress},
	}

	// Use NewProxyConn to properly initialize internal fields (tracker)
	connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
	proxyConn := connect.NewProxyConn(serverConn, nil, nil, zap.NewNop(), connMetrics)
	proxyConn.Claims = claims
	proxyConn.ID = "test-conn-id"
	proxyConn.Address = apiServerAddress

	// Send the connection through the channel (this is what connect.Listener does)
	go func() {
		ch <- proxyConn
	}()

	// Client sends HTTP request through the pipe
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return clientConn, nil
			},
		},
	}

	// Send GET request
	resp, err := client.Get("http://proxy/api/v1/pods")
	require.NoError(t, err)

	defer resp.Body.Close()

	// Verify response
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Upstream API Server Response!", string(body))
}

func TestShouldSkipWebSocketRequest(t *testing.T) {
	tests := []struct {
		name         string
		newRequestFn func() *http.Request
		expected     bool
	}{
		{
			name: "WebSocket request with tunneling protocol",
			newRequestFn: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Connection", "upgrade")
				r.Header.Set("Sec-WebSocket-Protocol", "SPDY/3.1+portforward.k8s.io")

				return r
			},
			expected: true,
		},
		{
			name: "WebSocket request with `kubectl cp` command",
			newRequestFn: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Kubectl-Command", "kubectl cp")

				return r
			},
			expected: true,
		},
		{
			name: "WebSocket request with tar command",
			newRequestFn: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods/pod-1/exec?command=tar", nil)
			},
			expected: true,
		},
		{
			name: "WebSocket request with other command",
			newRequestFn: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods/pod-1/exec?command=ls", nil)
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldSkipWebSocketRequest(tt.newRequestFn())
			assert.Equal(t, tt.expected, result)
		})
	}
}
