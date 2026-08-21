// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapphandler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
		requestHeaders:      map[string]*template.Template{"X-Bad": unknownKeyTemplate},
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
				"X-GAT-Username": "{{username}}",
				"X-GAT-Auth":     "Bearer {{jwt}}",
			}),
			headers: map[string]string{},
			wantHeaders: map[string]string{
				"X-GAT-Static":   "static-value",
				"X-GAT-Username": "alice@acme.com",
				"X-GAT-Auth":     "Bearer test-token",
			},
		},
		{
			name:     "GAT request header rewrites override config headers on conflict",
			jwtToken: "test-token",
			claims: withRequestHeaderRewrites(baseClaims, map[string]string{
				"X-Username": "{{username}}",
			}),
			headers: map[string]string{
				"X-Config":   "Dont override",
				"X-Username": "Overridden by GAT Token",
			},
			wantHeaders: map[string]string{
				"X-Config":   "Dont override",
				"X-Username": "alice@acme.com",
			},
		},
		{
			name:     "preserve config header when conflict with unsupported GAT request header rewrites",
			jwtToken: "test-token",
			claims: withRequestHeaderRewrites(baseClaims, map[string]string{
				"X-Malformed": "{{unclosed",
				"X-Unknown":   "{{nonexistent}}",
			}),
			headers: map[string]string{
				"X-Malformed": "Config value",
				"X-Unknown":   "Config value",
			},
			wantHeaders: map[string]string{
				"X-Malformed": "Config value",
				"X-Unknown":   "Config value",
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

func TestRewrite_PreservesClientHost(t *testing.T) {
	connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
	conn := connect.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	conn.Address = "admin.example.int:80"
	conn.Claims = &token.GATClaims{}

	proxyReq := &httputil.ProxyRequest{
		In:  httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil),
		Out: httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil),
	}

	err := rewrite(proxyReq, conn, nil)
	require.NoError(t, err)

	assert.Equal(t, "admin.example.int", proxyReq.Out.Host, "client Host must be preserved without the upstream port")
	assert.Equal(t, "admin.example.int:80", proxyReq.Out.URL.Host, "dial target must keep the port")
}

func TestRewrite_UpstreamScheme(t *testing.T) {
	tests := []struct {
		name        string
		upstreamTLS bool
		wantScheme  string
	}{
		{name: "plain HTTP when tls is false", upstreamTLS: false, wantScheme: "http"},
		{name: "HTTPS when tls is true", upstreamTLS: true, wantScheme: "https"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
			conn := connect.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
			conn.Address = "admin.example.int:8443"
			conn.Claims = &token.GATClaims{
				Resource: token.Resource{
					GatewayMetadata: token.GatewayMetadata{
						Upstream: token.Upstream{Port: 8443, TLS: tt.upstreamTLS},
					},
				},
			}

			proxyReq := &httputil.ProxyRequest{
				In:  httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil),
				Out: httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil),
			}

			err := rewrite(proxyReq, conn, nil)
			require.NoError(t, err)

			assert.Equal(t, tt.wantScheme, proxyReq.Out.URL.Scheme)
			assert.Equal(t, "admin.example.int:8443", proxyReq.Out.URL.Host)
		})
	}
}

func TestRewrite_StripsClientIdentityHeaders(t *testing.T) {
	connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
	conn := connect.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	conn.Address = "admin.example.int:80"
	conn.Claims = &token.GATClaims{}

	outReq := httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil)
	for _, headerName := range clientIdentityHeaders {
		outReq.Header.Set(headerName, "spoofed")
	}

	proxyReq := &httputil.ProxyRequest{
		In:  httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil),
		Out: outReq,
	}

	err := rewrite(proxyReq, conn, nil)
	require.NoError(t, err)

	for _, headerName := range clientIdentityHeaders {
		assert.Empty(t, proxyReq.Out.Header.Values(headerName), "client-supplied %s must be stripped", headerName)
	}
}

func TestRewrite_SkipsInvalidGATHeaders(t *testing.T) {
	baseClaims := &token.GATClaims{
		User: token.User{ID: "user-1", Username: "alice@acme.com"},
	}

	connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
	conn := connect.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	conn.Token = "test-token"
	conn.Claims = withRequestHeaderRewrites(baseClaims, map[string]string{
		"X-Malformed": "{{unclosed",
		"X-Unknown":   "{{nonexistent}}",
	})

	proxyReq := &httputil.ProxyRequest{
		In:  httptest.NewRequest(http.MethodGet, "http://test/api/resource", nil),
		Out: httptest.NewRequest(http.MethodGet, "http://test/api/resource", nil),
	}

	err := rewrite(proxyReq, conn, nil)
	require.NoError(t, err)

	assert.Empty(t, proxyReq.Out.Header.Values("X-Malformed"), "malformed header should not be set")
	assert.Empty(t, proxyReq.Out.Header.Values("X-Unknown"), "unknown header should not be set")
}

func TestCreateTransport(t *testing.T) {
	caPool := x509.NewCertPool()
	transport := createTransport(caPool)

	require.NotNil(t, transport.TLSClientConfig)
	assert.Same(t, caPool, transport.TLSClientConfig.RootCAs)
	assert.Equal(t, uint16(tls.VersionTLS13), transport.TLSClientConfig.MinVersion)
}

func TestBuildVariables_CoversAllowedKeys(t *testing.T) {
	connMetrics := connect.CreateProxyConnMetrics(prometheus.NewRegistry())
	conn := connect.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	conn.Claims = &token.GATClaims{}

	got := slices.Sorted(maps.Keys(buildVariables(conn)))
	want := slices.Sorted(slices.Values(template.AllowedWebAppKeys))

	assert.Equal(t, want, got)
}
