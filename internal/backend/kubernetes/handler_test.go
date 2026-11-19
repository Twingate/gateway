// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package kubernetes

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/frontend"
	"gateway/internal/token"
)

func TestRewrite(t *testing.T) {
	connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
	conn := frontend.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	conn.RequestedHost = "kubernetes.default.svc"
	conn.UpstreamHost = "kubernetes.default.svc"
	conn.Claims = &token.GATClaims{
		User: token.User{
			Username: "user@acme.com",
			Groups:   []string{"Everyone", "Engineering"},
		},
		Resource: token.Resource{
			Address:         "kubernetes.default.svc",
			GatewayMetadata: token.GatewayMetadata{Upstream: token.Upstream{Port: 443}},
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
		transport, err := createTransport("test-token", "", "../../../test/data/api_server/tls.crt")

		require.NoError(t, err)
		assert.NotNil(t, transport)
	})

	t.Run("Fails with nonexistent CA file", func(t *testing.T) {
		transport, err := createTransport("test-token", "", "/nonexistent/ca.crt")

		require.Error(t, err)
		assert.Nil(t, transport)
	})

	t.Run("Fails with invalid CA PEM content", func(t *testing.T) {
		transport, err := createTransport("test-token", "", "../../../test/data/proxy/tls.key")

		require.Error(t, err)
		require.ErrorIs(t, err, errUpstreamTLSConfigFailed)
		assert.Nil(t, transport)
	})
}

func TestShouldSkipWebSocketRequest(t *testing.T) {
	const execPath = "/api/v1/namespaces/default/pods/pod-1/exec"

	tests := []struct {
		name     string
		target   string
		headers  map[string]string
		expected bool
	}{
		{
			name:     "Port-forward request",
			target:   "/api/v1/namespaces/default/pods/pod-1/portforward",
			expected: true,
		},
		{
			name:     "Exec request with `kubectl cp` command",
			target:   execPath + "?command=tar&command=cf&command=-&command=%2Fetc%2Fhostname",
			expected: true,
		},
		{
			name:     "Exec request with other tar command",
			target:   execPath + "?command=tar&command=cf&command=-&command=%2Fetc%2Fhostname&command=--checkpoint-action%3Dexec%3Dsh",
			expected: false,
		},
		{
			name:     "Exec request with other command",
			target:   execPath + "?command=ls",
			expected: false,
		},
		{
			name:     "Exec request with `kubectl cp` header",
			target:   execPath + "?command=ls",
			headers:  map[string]string{"Kubectl-Command": "kubectl cp"},
			expected: false,
		},
		{
			name:     "Exec request offering a tunneling protocol",
			target:   execPath + "?command=ls",
			headers:  map[string]string{"Sec-WebSocket-Protocol": "v5.channel.k8s.io, SPDY/3.1+portforward.k8s.io"},
			expected: false,
		},
		{
			name:     "Attach request with `kubectl cp` command",
			target:   "/api/v1/namespaces/default/pods/pod-1/attach?command=tar&command=cf&command=-&command=%2Fetc%2Fhostname",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.target, nil)
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Connection", "upgrade")

			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}

			assert.Equal(t, tt.expected, shouldSkipWebSocketRequest(r))
		})
	}
}

func TestIsKubectlCpCommand(t *testing.T) {
	tests := []struct {
		name     string
		command  []string
		expected bool
	}{
		{
			name:     "Copy from the container",
			command:  []string{"tar", "cf", "-", "/etc/hostname"},
			expected: true,
		},
		{
			name:     "Copy to the container",
			command:  []string{"tar", "-xmf", "-"},
			expected: true,
		},
		{
			name:     "Copy to a directory in the container",
			command:  []string{"tar", "-xmf", "-", "-C", "/tmp"},
			expected: true,
		},
		{
			name:     "Copy to the container without preserving ownership and permissions",
			command:  []string{"tar", "--no-same-permissions", "--no-same-owner", "-xmf", "-"},
			expected: true,
		},
		{
			name:     "Copy to a directory in the container without preserving ownership and permissions",
			command:  []string{"tar", "--no-same-permissions", "--no-same-owner", "-xmf", "-", "-C", "/tmp"},
			expected: true,
		},
		{
			name:     "No command",
			command:  nil,
			expected: false,
		},
		{
			name:     "Only tar",
			command:  []string{"tar"},
			expected: false,
		},
		{
			name:     "Option in place of the path to copy from",
			command:  []string{"tar", "cf", "-", "--use-compress-program=sh"},
			expected: false,
		},
		{
			name:     "Extra argument when copying from the container",
			command:  []string{"tar", "cf", "-", "/etc/hostname", "--checkpoint-action=exec=sh"},
			expected: false,
		},
		{
			name:     "Extra argument when copying to the container",
			command:  []string{"tar", "-xmf", "-", "--to-command=sh"},
			expected: false,
		},
		{
			name:     "Extra argument before the directory to copy to",
			command:  []string{"tar", "-xmf", "-", "--to-command=sh", "-C", "/tmp"},
			expected: false,
		},
		{
			name:     "Missing directory to copy to",
			command:  []string{"tar", "-xmf", "-", "-C"},
			expected: false,
		},
		{
			name:     "Different flags for the same operation",
			command:  []string{"tar", "-cf", "-", "/etc/hostname"},
			expected: false,
		},
		{
			name:     "Shell running tar",
			command:  []string{"sh", "-c", "tar cf - '/etc/hostname' | tail -c+0"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isKubectlCpCommand(tt.command))
		})
	}
}
