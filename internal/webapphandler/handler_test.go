// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapphandler

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"slices"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/connect"
	"gateway/internal/httpproxy"
	"gateway/internal/metrics"
	"gateway/internal/token"
	"gateway/internal/webapphandler/template"
)

func mustParse(t *testing.T, templates map[string]string) map[string]*template.Template {
	t.Helper()

	result := make(map[string]*template.Template, len(templates))

	for name, tmpl := range templates {
		parsed, err := template.New(tmpl)
		require.NoError(t, err, "failed to parse template for header %q", name)

		result[name] = parsed
	}

	return result
}

func TestNewHandler_PanicsOnRewriteError(t *testing.T) {
	connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
	conn := connect.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	conn.Claims = &token.GATClaims{
		User: token.User{Username: "alice@acme.com"},
	}

	unknownKeyTemplate, err := template.New("{{nonexistent}}")
	require.NoError(t, err)

	handler := NewHandler(Config{
		headers:             map[string]*template.Template{"X-Bad": unknownKeyTemplate},
		roundTripperMetrics: metrics.RegisterRoundTripperMetrics(prometheus.NewRegistry()),
		logger:              zap.NewNop(),
	})

	req := httptest.NewRequest(http.MethodGet, "http://test/api", nil)
	ctx := context.WithValue(req.Context(), httpproxy.ConnContextKey{}, conn)
	req = req.WithContext(ctx)

	assert.Panics(t, func() {
		handler.ServeHTTP(httptest.NewRecorder(), req)
	})
}

func withRequestHeaderRewrites(base *token.GATClaims, rewrites map[string]string) *token.GATClaims {
	claims := *base
	claims.Resource.GatewayMetadata.RequestHeaderRewrites = rewrites

	return &claims
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
			Location: token.GeoIPLocation{Lat: 37.5, Lon: -122.4, Country: "US", Region: "CA", City: "San Mateo"},
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
				"Authorization": "Bearer {{jwt}}",
				"X-Username":    "{{username}}",
				"X-Groups":      "{{groups}}",
				"X-LatLong":     "{{clientGeoLatLong}}",
				"X-City":        "{{clientGeoCity}}",
				"X-Region":      "{{clientGeoRegion}}",
				"X-Country":     "{{clientGeoCountry}}",
				"Existing":      "new-value",
			},
			wantHeaders: map[string]string{
				"Authorization": "Bearer test-token",
				"X-Username":    "alice@acme.com",
				"X-Groups":      "Everyone,Engineering",
				"X-LatLong":     "37.5,-122.4",
				"X-City":        "San Mateo",
				"X-Region":      "CA",
				"X-Country":     "US",
				"Existing":      "new-value",
			},
		},
		{
			name:     "applies GAT request header rewrites with template values",
			jwtToken: "test-token",
			claims: withRequestHeaderRewrites(baseClaims, map[string]string{
				"X-GAT-Static":   "static-value",
				"X-Username":     "{{username}}",
				"X-GAT-Username": "{{username}}",
				"X-GAT-Auth":     "Bearer {{jwt}}",
			}),
			headers: map[string]string{
				"X-Config":   "Dont override",
				"X-Username": "Overridden by GAT Token",
			},
			wantHeaders: map[string]string{
				"X-Config":       "Dont override",
				"X-Username":     "alice@acme.com",
				"X-GAT-Username": "alice@acme.com",
				"X-GAT-Auth":     "Bearer test-token",
			},
		},
		{
			name:     "skips malformed and unsupported GAT request header rewrites",
			jwtToken: "test-token",
			claims: withRequestHeaderRewrites(baseClaims, map[string]string{
				"X-GAT-Good":      "{{username}}",
				"X-GAT-Malformed": "{{unclosed",
				"X-GAT-Unknown":   "{{nonexistent}}",
			}),
			headers: map[string]string{},
			wantHeaders: map[string]string{
				"X-GAT-Good":      "alice@acme.com",
				"X-GAT-Malformed": "",
				"X-GAT-Unknown":   "",
			},
		},
		{
			name:     "empty lat/lon with non-empty geo fields",
			jwtToken: "test-token",
			claims: &token.GATClaims{
				User:   baseClaims.User,
				Device: token.Device{ID: "device-1", Location: token.GeoIPLocation{Country: "US", Region: "CA", City: "San Mateo"}},
			},
			headers: map[string]string{
				"X-LatLong": "{{clientGeoLatLong}}",
				"X-City":    "{{clientGeoCity}}",
				"X-Region":  "{{clientGeoRegion}}",
				"X-Country": "{{clientGeoCountry}}",
			},
			wantHeaders: map[string]string{
				"X-LatLong": "",
				"X-City":    "San Mateo",
				"X-Region":  "CA",
				"X-Country": "US",
				"Existing":  "old-value",
			},
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

func TestBuildVariables_CoversAllowedKeys(t *testing.T) {
	connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
	conn := connect.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	conn.Claims = &token.GATClaims{}

	got := slices.Sorted(maps.Keys(buildVariables(conn)))
	want := slices.Sorted(slices.Values(template.AllowedWebAppKeys))

	assert.Equal(t, want, got)
}
