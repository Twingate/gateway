// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package kuberneteshandler

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/connect"
	"gateway/internal/token"
)

func TestRewrite(t *testing.T) {
	connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
	conn := connect.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	conn.Address = "kubernetes.default.svc"
	conn.Claims = &token.GATClaims{
		User: token.User{
			Username: "user@acme.com",
			Groups:   []string{"Everyone", "Engineering"},
		},
		Resource: token.Resource{
			Address: "kubernetes.default.svc",
		},
	}

	outReq := httptest.NewRequest(http.MethodGet, "http://test/api/v1/pods", nil)
	outReq.Header.Set("Authorization", "Bearer test")
	outReq.Header.Set("Impersonate-User", "Admin")
	outReq.Header.Set("Impersonate-Group", "Admin-Group")
	outReq.Header.Set("Impersonate-Uid", "uid-123")
	outReq.Header.Set("Impersonate-Extra-Scopes", "cluster-admin")

	proxyReq := &httputil.ProxyRequest{
		In:  httptest.NewRequest(http.MethodGet, "http://test/api/v1/pods", nil),
		Out: outReq,
	}

	rewrite(proxyReq, conn)

	assert.Equal(t, "user@acme.com", proxyReq.Out.Header.Get("Impersonate-User"))
	assert.Equal(t, []string{"Everyone", "Engineering"}, proxyReq.Out.Header.Values("Impersonate-Group"))
	assert.Empty(t, proxyReq.Out.Header.Get("Authorization"))
	assert.Empty(t, proxyReq.Out.Header.Get("Impersonate-Uid"))
	assert.Empty(t, proxyReq.Out.Header.Get("Impersonate-Extra-Scopes"))
}

func TestCreateTransport(t *testing.T) {
	t.Run("Success with bearer token", func(t *testing.T) {
		transport, err := createTransport("test-token", "", "../../test/data/api_server/tls.crt")

		require.NoError(t, err)
		assert.NotNil(t, transport)
	})

	t.Run("Fails with nonexistent CA file", func(t *testing.T) {
		transport, err := createTransport("test-token", "", "/nonexistent/ca.crt")

		require.Error(t, err)
		assert.Nil(t, transport)
	})

	t.Run("Fails with invalid CA PEM content", func(t *testing.T) {
		transport, err := createTransport("test-token", "", "../../test/data/proxy/tls.key")

		require.Error(t, err)
		require.ErrorIs(t, err, errUpstreamTLSConfigFailed)
		assert.Nil(t, transport)
	})
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
