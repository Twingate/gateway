// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"gateway/internal/backend/httpproxy"
	"gateway/internal/backend/webapp/template"
	"gateway/internal/frontend"
	"gateway/internal/logging"
	"gateway/internal/metrics"
	"gateway/internal/token"
	"gateway/test/data"
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
	connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
	conn := frontend.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	conn.Claims = &token.GATClaims{
		User: token.User{Username: "alice@acme.com"},
	}

	unknownKeyTemplate, err := template.New("{{nonexistent}}")
	require.NoError(t, err)

	handler := NewHandler(Config{
		requestHeaders:      map[string]*template.Template{"X-Bad": unknownKeyTemplate},
		roundTripperMetrics: metrics.RegisterRoundTripperMetrics(prometheus.NewRegistry()),
	})

	core, logs := observer.New(zap.ErrorLevel)
	logger := logging.Logger{System: zap.NewNop(), Audit: zap.New(core), Session: zap.NewNop()}

	req := httptest.NewRequest(http.MethodGet, "http://test/api", nil)
	ctx := context.WithValue(req.Context(), httpproxy.ConnContextKey{}, conn)
	ctx = context.WithValue(ctx, httpproxy.LoggerKey{}, logger)
	req = req.WithContext(ctx)

	assert.Panics(t, func() {
		handler.ServeHTTP(httptest.NewRecorder(), req)
	})
	assert.Equal(t, 1, logs.FilterMessage("failed to rewrite headers").Len())
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
		name         string
		upstreamHost string
		jwtToken     string
		claims       *token.GATClaims
		headers      map[string]string
		wantHeaders  map[string]string
		wantHost     string
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
		{
			name:     "config Host rewrite sets the outbound Host and not the header map",
			jwtToken: "test-token",
			claims:   baseClaims,
			headers: map[string]string{
				"Host": "kibana.corp.internal",
			},
			wantHeaders: map[string]string{
				"Host": "",
			},
			wantHost: "kibana.corp.internal",
		},
		{
			name:     "GAT Host rewrite overrides config Host",
			jwtToken: "test-token",
			claims: withRequestHeaderRewrites(baseClaims, map[string]string{
				"Host": "kibana.corp.internal",
			}),
			headers: map[string]string{
				"Host": "config.corp.internal",
			},
			wantHost: "kibana.corp.internal",
		},
		{
			name:     "lowercase host rewrite is treated as Host",
			jwtToken: "test-token",
			claims: withRequestHeaderRewrites(baseClaims, map[string]string{
				"host": "kibana.corp.internal",
			}),
			headers:  map[string]string{},
			wantHost: "kibana.corp.internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
			conn := frontend.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
			conn.UpstreamHost = tt.upstreamHost
			conn.Token = tt.jwtToken
			conn.Claims = tt.claims

			outReq := httptest.NewRequest(http.MethodGet, "http://test/api/resource", nil)
			outReq.Header.Set("Existing", "old-value")

			proxyReq := &httputil.ProxyRequest{
				In:  httptest.NewRequest(http.MethodGet, "http://test/api/resource", nil),
				Out: outReq,
			}
			parsedHeaders := mustParse(t, tt.headers)

			require.NoError(t, rewrite(proxyReq, conn, parsedHeaders, zap.NewNop()))

			for name, wantValue := range tt.wantHeaders {
				assert.Equal(t, wantValue, proxyReq.Out.Header.Get(name))
			}

			if tt.wantHost != "" {
				assert.Equal(t, tt.wantHost, proxyReq.Out.Host)
			}
		})
	}
}

func TestRewrite_PreservesClientHost(t *testing.T) {
	connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
	conn := frontend.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	conn.UpstreamHost = "admin.example.int"
	conn.Claims = &token.GATClaims{
		Resource: token.Resource{GatewayMetadata: token.GatewayMetadata{Upstream: token.Upstream{Port: 80, TLSMode: token.TLSClientModeNone}}},
	}

	proxyReq := &httputil.ProxyRequest{
		In:  httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil),
		Out: httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil),
	}

	err := rewrite(proxyReq, conn, nil, zap.NewNop())
	require.NoError(t, err)

	assert.Equal(t, "admin.example.int", proxyReq.Out.Host, "client Host must be preserved without the upstream port")
	assert.Equal(t, "admin.example.int:80", proxyReq.Out.URL.Host, "dial target must keep the port")
}

func TestRewrite_UpstreamScheme(t *testing.T) {
	tests := []struct {
		name            string
		upstreamTLSMode token.TLSClientMode
		wantScheme      string
	}{
		{name: "plain HTTP when TLS mode is none", upstreamTLSMode: token.TLSClientModeNone, wantScheme: "http"},
		{name: "HTTPS when TLS mode is verify_full", upstreamTLSMode: token.TLSClientModeVerifyFull, wantScheme: "https"},
		{name: "HTTPS when TLS mode is verify_ca", upstreamTLSMode: token.TLSClientModeVerifyCA, wantScheme: "https"},
		{name: "HTTPS when TLS mode is insecure", upstreamTLSMode: token.TLSClientModeInsecure, wantScheme: "https"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
			conn := frontend.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
			conn.UpstreamHost = "admin.example.int"
			conn.Claims = &token.GATClaims{
				Resource: token.Resource{
					GatewayMetadata: token.GatewayMetadata{
						Upstream: token.Upstream{Port: 8443, TLSMode: tt.upstreamTLSMode},
					},
				},
			}

			proxyReq := &httputil.ProxyRequest{
				In:  httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil),
				Out: httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil),
			}

			err := rewrite(proxyReq, conn, nil, zap.NewNop())
			require.NoError(t, err)

			assert.Equal(t, tt.wantScheme, proxyReq.Out.URL.Scheme)
			assert.Equal(t, "admin.example.int:8443", proxyReq.Out.URL.Host)
		})
	}
}

func TestRewrite_StripsClientIdentityHeaders(t *testing.T) {
	connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
	conn := frontend.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	conn.UpstreamHost = "admin.example.int"
	conn.Claims = &token.GATClaims{
		Resource: token.Resource{GatewayMetadata: token.GatewayMetadata{Upstream: token.Upstream{Port: 80, TLSMode: token.TLSClientModeNone}}},
	}

	outReq := httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil)
	for _, headerName := range clientIdentityHeaders {
		outReq.Header.Set(headerName, "spoofed")
	}

	proxyReq := &httputil.ProxyRequest{
		In:  httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil),
		Out: outReq,
	}

	err := rewrite(proxyReq, conn, nil, zap.NewNop())
	require.NoError(t, err)

	for _, headerName := range clientIdentityHeaders {
		assert.Empty(t, proxyReq.Out.Header.Values(headerName), "client-supplied %s must be stripped", headerName)
	}
}

func TestRewrite_SkipsInvalidGATHeaders(t *testing.T) {
	baseClaims := &token.GATClaims{
		User: token.User{ID: "user-1", Username: "alice@acme.com"},
	}

	connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
	conn := frontend.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	conn.Token = "test-token"
	conn.Claims = withRequestHeaderRewrites(baseClaims, map[string]string{
		"X-Malformed": "{{unclosed",
		"X-Unknown":   "{{nonexistent}}",
	})

	proxyReq := &httputil.ProxyRequest{
		In:  httptest.NewRequest(http.MethodGet, "http://test/api/resource", nil),
		Out: httptest.NewRequest(http.MethodGet, "http://test/api/resource", nil),
	}

	err := rewrite(proxyReq, conn, nil, zap.NewNop())
	require.NoError(t, err)

	assert.Empty(t, proxyReq.Out.Header.Values("X-Malformed"), "malformed header should not be set")
	assert.Empty(t, proxyReq.Out.Header.Values("X-Unknown"), "unknown header should not be set")
}

func newTLSTestServer(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)

	return server
}

func TestCreateUpstreamRoundTripper(t *testing.T) {
	cert, err := tls.X509KeyPair(data.ProxyCert, data.ProxyKey)
	require.NoError(t, err)

	server := newTLSTestServer(t, cert)

	roundTripper := createUpstreamRoundTripper(x509.NewCertPool())

	roundTrip := func(t *testing.T, mode token.TLSClientMode) (int, error) {
		t.Helper()

		connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
		conn := frontend.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
		conn.Claims = &token.GATClaims{
			Resource: token.Resource{GatewayMetadata: token.GatewayMetadata{Upstream: token.Upstream{TLSMode: mode}}},
		}

		ctx := context.WithValue(t.Context(), httpproxy.ConnContextKey{}, conn)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		require.NoError(t, err)

		resp, err := roundTripper.RoundTrip(req)
		if err != nil {
			return 0, err
		}

		_ = resp.Body.Close()

		return resp.StatusCode, nil
	}

	t.Run("insecure skips certificate verification", func(t *testing.T) {
		statusCode, err := roundTrip(t, token.TLSClientModeInsecure)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, statusCode)
	})

	t.Run("verify_full rejects an untrusted certificate", func(t *testing.T) {
		_, err := roundTrip(t, token.TLSClientModeVerifyFull)

		var unknownAuthorityErr x509.UnknownAuthorityError
		assert.ErrorAs(t, err, &unknownAuthorityErr)
	})

	t.Run("unknown TLS mode is rejected", func(t *testing.T) {
		_, err := roundTrip(t, "bogus")

		assert.ErrorIs(t, err, errUnsupportedTLSMode)
	})
}

func TestCreateTransport(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	transport := createTransport(tlsConfig)

	assert.Same(t, tlsConfig, transport.TLSClientConfig)
	assert.NotSame(t, http.DefaultTransport, transport)
}

func TestNewUpstreamTLSConfig(t *testing.T) {
	cert, err := tls.X509KeyPair(data.ProxyCert, data.ProxyKey)
	require.NoError(t, err)

	server := newTLSTestServer(t, cert)

	trustedPool := x509.NewCertPool()
	require.True(t, trustedPool.AppendCertsFromPEM(data.ProxyCert))

	tests := []struct {
		name       string
		mode       token.TLSClientMode
		rootCAs    *x509.CertPool
		serverName string
		wantErr    bool
	}{
		{name: "verify_full accepts a trusted certificate matching the hostname", mode: token.TLSClientModeVerifyFull, rootCAs: trustedPool, serverName: "localhost"},
		{name: "verify_full rejects a hostname mismatch", mode: token.TLSClientModeVerifyFull, rootCAs: trustedPool, serverName: "corp.internal", wantErr: true},
		{name: "verify_full rejects an untrusted certificate", mode: token.TLSClientModeVerifyFull, rootCAs: x509.NewCertPool(), serverName: "localhost", wantErr: true},
		{name: "verify_ca accepts a hostname mismatch", mode: token.TLSClientModeVerifyCA, rootCAs: trustedPool, serverName: "corp.internal"},
		{name: "verify_ca rejects an untrusted certificate", mode: token.TLSClientModeVerifyCA, rootCAs: x509.NewCertPool(), serverName: "corp.internal", wantErr: true},
		{name: "insecure accepts an untrusted certificate with a hostname mismatch", mode: token.TLSClientModeInsecure, rootCAs: x509.NewCertPool(), serverName: "corp.internal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig := newUpstreamTLSConfig(tt.mode, tt.rootCAs)
			require.NotNil(t, tlsConfig)
			assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)

			tlsConfig.ServerName = tt.serverName
			dialer := &tls.Dialer{Config: tlsConfig}

			conn, err := dialer.DialContext(t.Context(), "tcp", server.Listener.Addr().String())
			if tt.wantErr {
				assert.Error(t, err)

				return
			}

			require.NoError(t, err)

			_ = conn.Close()
		})
	}

	t.Run("verify_ca accepts a certificate issued by an intermediate CA", func(t *testing.T) {
		serverCert, rootCAs := newCertificateChain(t)
		chainServer := newTLSTestServer(t, serverCert)

		tlsConfig := newUpstreamTLSConfig(token.TLSClientModeVerifyCA, rootCAs)
		tlsConfig.ServerName = "corp.internal"
		dialer := &tls.Dialer{Config: tlsConfig}

		conn, err := dialer.DialContext(t.Context(), "tcp", chainServer.Listener.Addr().String())
		require.NoError(t, err)

		_ = conn.Close()
	})

	t.Run("none returns no TLS config", func(t *testing.T) {
		assert.Nil(t, newUpstreamTLSConfig(token.TLSClientModeNone, trustedPool))
	})
}

// newCertificateChain returns a leaf certificate issued by an intermediate CA, served together with
// that intermediate, and a pool holding only the root CA that issued the intermediate.
func newCertificateChain(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	issue := func(tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		if parent == nil {
			parent, parentKey = tmpl, key
		}

		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)

		return cert, key
	}

	ca := &x509.Certificate{NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	root, rootKey := issue(ca, nil, nil)
	intermediate, intermediateKey := issue(ca, root, rootKey)
	leaf, leafKey := issue(&x509.Certificate{NotAfter: ca.NotAfter}, intermediate, intermediateKey)

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(root)

	return tls.Certificate{Certificate: [][]byte{leaf.Raw, intermediate.Raw}, PrivateKey: leafKey}, rootCAs
}

func TestBuildVariables_CoversAllowedKeys(t *testing.T) {
	connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
	conn := frontend.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
	conn.Claims = &token.GATClaims{}

	got := slices.Sorted(maps.Keys(buildVariables(conn)))
	want := slices.Sorted(slices.Values(template.AllowedWebAppKeys))

	assert.Equal(t, want, got)
}

func TestRewrite_SetsXForwardedProto(t *testing.T) {
	tests := []struct {
		name              string
		downstreamTLSMode token.TLSServerMode
		clientSuppliedXFP string
		want              string
	}{
		{
			name:              "HTTPS when the Gateway terminates TLS downstream",
			downstreamTLSMode: token.TLSServerModeTLS13,
			want:              "https",
		},
		{
			name:              "HTTP when the protocol client connects in plaintext",
			downstreamTLSMode: token.TLSServerModeNone,
			want:              "http",
		},
		{
			name:              "client-supplied value is overwritten",
			downstreamTLSMode: token.TLSServerModeNone,
			clientSuppliedXFP: "https",
			want:              "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
			conn := frontend.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
			conn.UpstreamHost = "admin.example.int"
			conn.Claims = &token.GATClaims{
				Resource: token.Resource{
					Type: token.ResourceTypeWebApp,
					GatewayMetadata: token.GatewayMetadata{
						Downstream: token.Downstream{Port: 443, TLSMode: tt.downstreamTLSMode},
						Upstream:   token.Upstream{Port: 80, TLSMode: token.TLSClientModeNone},
					},
				},
			}

			outReq := httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil)
			if tt.clientSuppliedXFP != "" {
				outReq.Header.Set("X-Forwarded-Proto", tt.clientSuppliedXFP)
			}

			proxyReq := &httputil.ProxyRequest{
				In:  httptest.NewRequest(http.MethodGet, "http://admin.example.int/path", nil),
				Out: outReq,
			}

			err := rewrite(proxyReq, conn, nil, zap.NewNop())
			require.NoError(t, err)

			assert.Equal(t, tt.want, proxyReq.Out.Header.Get("X-Forwarded-Proto"))
		})
	}
}
