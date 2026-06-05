// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gateway/internal/metrics/testutil"
)

func TestIsSpdyRequest(t *testing.T) {
	tests := []struct {
		name         string
		newRequestFn func() *http.Request
		expected     bool
	}{
		{
			name: "SPDY request",
			newRequestFn: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Upgrade", "spdy/3.1")
				r.Header.Set("Connection", "upgrade")

				return r
			},
			expected: true,
		},
		{
			name: "Websocket request",
			newRequestFn: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Connection", "upgrade")

				return r
			},
			expected: false,
		},
		{
			name: "HTTP request",
			newRequestFn: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)

				return r
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSpdyRequest(tt.newRequestFn())
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWithRequestType(t *testing.T) {
	testCases := []struct {
		name                string
		setupRequest        func(*http.Request)
		expectedRequestType string
	}{
		{
			name:                "HTTP Request",
			setupRequest:        func(_ *http.Request) {}, // No special headers for regular HTTP
			expectedRequestType: "http",
		},
		{
			name: "WebSocket Request",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Connection", "upgrade")
			},
			expectedRequestType: "websocket",
		},
		{
			name: "SPDY Request",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Upgrade", "spdy/3.1")
				req.Header.Set("Connection", "upgrade")
			},
			expectedRequestType: "spdy",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/", nil)
			require.NoError(t, err, "failed to create request")

			tc.setupRequest(req)

			req = requestWithTypeContext(req)

			value, ok := req.Context().Value(contextKey{}).(string)
			assert.True(t, ok)
			assert.Equal(t, tc.expectedRequestType, value)
		})
	}
}

func TestHTTPMiddleware(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	httpMetrics := RegisterHTTPMetrics(testRegistry)

	server := httptest.NewServer(HTTPMiddleware(
		httpMetrics,
		ResourceTypeKubernetes,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err, "failed to create request")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "failed to send request")

	defer resp.Body.Close()

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	labelsByMetric := testutil.ExtractLabelsFromMetrics(metricFamilies)
	expectedLabels := map[string]map[string]string{
		"twingate_gateway_http_requests_total": {
			"resource_type": "kubernetes",
			"type":          "http",
			"method":        "get",
			"code":          "200",
		},
		"twingate_gateway_http_active_requests": {
			"resource_type": "kubernetes",
			"type":          "http",
		},
		"twingate_gateway_http_request_duration_seconds": {
			"resource_type": "kubernetes",
			"type":          "http",
			"method":        "get",
			"code":          "200",
		},
		"twingate_gateway_http_request_size_bytes": {
			"resource_type": "kubernetes",
			"type":          "http",
			"method":        "get",
			"code":          "200",
		},
		"twingate_gateway_http_response_size_bytes": {
			"resource_type": "kubernetes",
			"type":          "http",
			"method":        "get",
			"code":          "200",
		},
	}
	assert.Equal(t, expectedLabels, labelsByMetric)
}
