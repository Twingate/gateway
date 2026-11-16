// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"gateway/internal/frontend"
	"gateway/internal/logging"
	"gateway/internal/metrics"
	"gateway/internal/token"
)

func TestMisdirectedRequestMiddleware(t *testing.T) {
	proxy := NewProxy(Config{
		Metrics:      metrics.RegisterHTTPMetrics(prometheus.NewRegistry()),
		ResourceType: metrics.ResourceTypeWebApp,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		Logger: logging.NewNop(),
	})

	tests := []struct {
		name            string
		resourceAddress string
		connectHost     string
		host            string
		wantStatus      int
	}{
		{
			name:            "Same hostname",
			resourceAddress: "app.corp.internal",
			connectHost:     "app.corp.internal",
			host:            "app.corp.internal",
			wantStatus:      http.StatusOK,
		},
		{
			name:            "Same hostname with a different port",
			resourceAddress: "app.corp.internal",
			connectHost:     "app.corp.internal",
			host:            "app.corp.internal:8443",
			wantStatus:      http.StatusOK,
		},
		{
			name:            "Same hostname in a different case",
			resourceAddress: "app.corp.internal",
			connectHost:     "app.corp.internal",
			host:            "App.Corp.Internal",
			wantStatus:      http.StatusOK,
		},
		{
			name:            "Alias of the resource",
			resourceAddress: "app.corp.internal",
			connectHost:     "app.corp.internal",
			host:            "app.internal",
			wantStatus:      http.StatusOK,
		},
		{
			name:            "Alias of the resource with a different port",
			resourceAddress: "app.corp.internal",
			connectHost:     "app.corp.internal",
			host:            "app.internal:8443",
			wantStatus:      http.StatusOK,
		},
		{
			name:            "Different hostname",
			resourceAddress: "app.corp.internal",
			connectHost:     "app.corp.internal",
			host:            "other.corp.internal",
			wantStatus:      http.StatusMisdirectedRequest,
		},
		{
			name:            "Different hostname with the same port",
			resourceAddress: "app.corp.internal",
			connectHost:     "app.corp.internal",
			host:            "other.corp.internal:8443",
			wantStatus:      http.StatusMisdirectedRequest,
		},
		{
			name:            "Same hostname of a wildcard resource",
			resourceAddress: "*.corp.internal",
			connectHost:     "app.corp.internal",
			host:            "app.corp.internal",
			wantStatus:      http.StatusOK,
		},
		{
			name:            "Different hostname of a wildcard resource",
			resourceAddress: "*.corp.internal",
			connectHost:     "app.corp.internal",
			host:            "other.corp.internal",
			wantStatus:      http.StatusMisdirectedRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connMetrics := frontend.CreateProxyConnMetrics(prometheus.NewRegistry())
			conn := frontend.NewProxyConn(nil, nil, nil, zap.NewNop(), connMetrics)
			conn.RequestedHost = tt.connectHost
			conn.Claims = &token.GATClaims{
				User: token.User{Username: "test@acme.com"},
				Resource: token.Resource{
					Type:    token.ResourceTypeWebApp,
					Address: tt.resourceAddress,
					Aliases: []string{"app.internal"},
				},
			}

			req := httptest.NewRequest(http.MethodGet, "http://"+tt.host+"/api", nil)
			req = req.WithContext(context.WithValue(req.Context(), ConnContextKey{}, conn))

			recorder := httptest.NewRecorder()
			proxy.httpServer.Handler.ServeHTTP(recorder, req)

			assert.Equal(t, tt.wantStatus, recorder.Code)
		})
	}
}
