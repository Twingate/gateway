// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"gateway/internal/frontend"
	"gateway/internal/logging"
	"gateway/internal/token"
)

// newBenchLogger returns a JSON logger that discards its output, so benchmarks include the
// cost of encoding audit fields.
func newBenchLogger() *zap.Logger {
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())

	return zap.New(zapcore.NewCore(encoder, zapcore.AddSync(io.Discard), zapcore.InfoLevel))
}

func BenchmarkAuditMiddleware(b *testing.B) {
	conn := &frontend.ProxyConn{
		ID: "conn-id-1",
		Claims: &token.GATClaims{
			User: token.User{ID: "user-id-1", Username: "user@acme.com", Groups: []string{"OnCall", "Engineering"}},
		},
	}
	ctx := context.WithValue(b.Context(), ConnContextKey{}, conn)

	logger := logging.Logger{System: zap.NewNop(), Audit: newBenchLogger(), Session: newBenchLogger()}
	handler := auditMiddleware(auditMiddlewareConfig{
		next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Audit-Id", "audit-id-1")
			w.WriteHeader(http.StatusOK)
		}),
		logger: logger,
	})

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/namespaces/default/pods?limit=500", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "kubectl/v1.37.0 (darwin/arm64) kubernetes/abcdef")
	req.Header.Set("Kubectl-Command", "kubectl get")

	b.ReportAllocs()

	for b.Loop() {
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
}
