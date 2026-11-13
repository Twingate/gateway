// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapp

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"gateway/internal/backend/webapp/template"
	"gateway/internal/frontend"
	"gateway/internal/token"
)

func BenchmarkRewrite(b *testing.B) {
	claims := &token.GATClaims{
		User: token.User{ID: "user-1", Username: "alice@acme.com", Groups: []string{"Everyone", "Engineering"}},
		Device: token.Device{
			ID:       "device-1",
			Location: token.GeoIPLocation{Lat: 37.5, Lon: -122.4, Country: "US", Region: "CA", City: "San Mateo"},
		},
	}
	claims.Resource.GatewayMetadata.RequestHeaderRewrites = map[string]string{
		"X-Forwarded-User":   "{{username}}",
		"X-Forwarded-Groups": "{{groups}}",
		"X-Client-Country":   "{{clientGeoCountry}}",
	}

	headers := make(map[string]*template.Template)

	for name, value := range map[string]string{"Authorization": "Bearer {{jwt}}", "X-Username": "{{username}}"} {
		tmpl, err := template.New(value)
		if err != nil {
			b.Fatal(err)
		}

		headers[name] = tmpl
	}

	conn := frontend.NewProxyConn(nil, nil, nil, zap.NewNop(), frontend.CreateProxyConnMetrics(prometheus.NewRegistry()))
	conn.UpstreamHost = "app.internal"
	conn.Token = "test-token"
	conn.Claims = claims

	in := httptest.NewRequest(http.MethodGet, "http://app.example.com/dashboard", nil)

	b.ReportAllocs()

	for b.Loop() {
		proxyReq := &httputil.ProxyRequest{In: in, Out: in.Clone(in.Context())}
		if err := rewrite(proxyReq, conn, headers, zap.NewNop()); err != nil {
			b.Fatal(err)
		}
	}
}
