// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapphandler

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
	"gateway/internal/httpproxy/parser"
	"gateway/internal/token"
)

func mustParse(t *testing.T, templates map[string]string) map[string]*parser.Template {
	t.Helper()

	result := make(map[string]*parser.Template, len(templates))

	for name, tmpl := range templates {
		parsed, err := parser.NewTemplate(tmpl)
		require.NoError(t, err, "failed to parse template for header %q", name)

		result[name] = parsed
	}

	return result
}

func TestRewrite(t *testing.T) {
	baseClaims := &token.GATClaims{
		User: token.User{
			ID:       "user-1",
			Username: "alice@acme.com",
			Groups:   []string{"Everyone", "Engineering"},
		},
		Device: token.Device{
			ID:       "device-1",
			Location: token.GeoIPLocation{Lat: 37.5, Lon: -122.4},
		},
	}

	tests := []struct {
		name        string
		address     string
		jwtToken    string
		claims      *token.GATClaims
		headers     map[string]string
		wantHeaders map[string]string
	}{
		{
			name:     "resolves all header templates",
			jwtToken: "test-token",
			claims:   baseClaims,
			headers: map[string]string{
				"Authorization": "Bearer {{twingate.jwt}}",
				"X-Username":    "{{twingate.username}}",
				"X-Groups":      "{{twingate.groups}}",
				"X-Geo":         "{{twingate.clientGeoLoc}}",
				"Existing":      "new-value",
			},
			wantHeaders: map[string]string{
				"Authorization": "Bearer test-token",
				"X-Username":    "alice@acme.com",
				"X-Groups":      "Everyone,Engineering",
				"X-Geo":         "37.5,-122.4",
				"Existing":      "new-value",
			},
		},
		{
			name:     "empty geo when no device location",
			jwtToken: "test-token",
			claims: &token.GATClaims{
				User:     baseClaims.User,
				Device:   token.Device{ID: "device-1"},
				Resource: baseClaims.Resource,
			},
			headers: map[string]string{
				"X-Geo": "{{twingate.clientGeoLoc}}",
			},
			wantHeaders: map[string]string{"X-Geo": ""},
		},
		{
			name:     "empty headers",
			jwtToken: "test-token",
			claims:   baseClaims,
			headers:  map[string]string{},
			wantHeaders: map[string]string{
				"Existing": "old-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
			conn := connect.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
			conn.Address = tt.address
			conn.Token = tt.jwtToken
			conn.Claims = tt.claims

			outReq := httptest.NewRequest(http.MethodGet, "http://test/api/resource", nil)
			outReq.Header.Set("Existing", "old-value")

			proxyReq := &httputil.ProxyRequest{
				In:  httptest.NewRequest(http.MethodGet, "http://test/api/resource", nil),
				Out: outReq,
			}
			parsedHeaders := mustParse(t, tt.headers)

			err := rewrite(proxyReq, conn, parsedHeaders)
			require.NoError(t, err)

			for name, wantValue := range tt.wantHeaders {
				assert.Equal(t, wantValue, proxyReq.Out.Header.Get(name))
			}
		})
	}
}
