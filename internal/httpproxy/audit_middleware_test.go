// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"gateway/internal/connect"
	"gateway/internal/token"
)

// Mock implementation of http.ResponseWriter that satisfies http.Hijacker.
type responseRecorder struct {
	httptest.ResponseRecorder
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}

func TestAuditMiddleware(t *testing.T) {
	tests := []struct {
		name               string
		handler            http.Handler
		expectedLogMessage string
		expectedLogLevel   zapcore.Level
		expectedStatusCode int
		expectedPanic      string
	}{
		{
			name: "Normal handler",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte("Accepted"))
			}),
			expectedLogMessage: "API request completed",
			expectedLogLevel:   zapcore.InfoLevel,
			expectedStatusCode: http.StatusAccepted,
			expectedPanic:      "",
		},
		{
			name: "Handler without explicitly setting response header",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("Response"))
			}),
			expectedLogMessage: "API request completed",
			expectedLogLevel:   zapcore.InfoLevel,
			expectedStatusCode: http.StatusOK,
			expectedPanic:      "",
		},
		{
			name: "Handler being hijacked",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hijacker, _ := w.(http.Hijacker)
				_, _, _ = hijacker.Hijack()
			}),
			expectedLogMessage: "API request completed",
			expectedLogLevel:   zapcore.InfoLevel,
			expectedStatusCode: http.StatusSwitchingProtocols,
			expectedPanic:      "",
		},
		{
			name: "Handler panics with http.ErrAbortHandler",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("Streaming..."))

				panic(http.ErrAbortHandler)
			}),
			expectedLogMessage: "API request completed",
			expectedLogLevel:   zapcore.InfoLevel,
			expectedStatusCode: http.StatusOK,
			expectedPanic:      "",
		},
		{
			name: "Handler panics with other error",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("Streaming..."))

				panic("Something went wrong!")
			}),
			expectedLogMessage: "API request failed",
			expectedLogLevel:   zapcore.ErrorLevel,
			expectedStatusCode: http.StatusOK,
			expectedPanic:      "Something went wrong!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &token.GATClaims{
				User: token.User{
					ID:       "user-id-1",
					Username: "user@acme.com",
					Groups:   []string{"OnCall", "Engineering"},
				},
			}
			conn := &connect.ProxyConn{ID: "conn-id-1", Claims: claims}
			ctx := context.WithValue(t.Context(), ConnContextKey, conn)
			request := httptest.NewRequestWithContext(ctx, "GET", "/api", nil)
			request.Header.Set("Kubectl-Command", "kubectl exec")

			recorder := &responseRecorder{ResponseRecorder: *httptest.NewRecorder()}
			recorder.Header().Set("Audit-Id", "audit-id-1")

			core, logs := observer.New(zap.DebugLevel)
			logger := zap.New(core)

			func() {
				defer func() {
					// Recover if handler panics
					_ = recover()
				}()

				auditMiddleware(tt.handler, logger).ServeHTTP(recorder, request)
			}()

			assert.Len(t, logs.All(), 1)
			log := logs.All()[0]
			assert.Equal(t, tt.expectedLogLevel, log.Level)
			assert.Equal(t, tt.expectedLogMessage, log.Message)

			logContext := log.ContextMap()
			assert.Subset(t, logContext, map[string]any{
				"method":      "GET",
				"url":         "/api",
				"remote_addr": request.RemoteAddr,
				"conn_id":     "conn-id-1",
				"user":        map[string]any{"id": "user-id-1", "username": "user@acme.com", "groups": []any{"OnCall", "Engineering"}},
				"request": map[string]any{
					"headers": http.Header{"Kubectl-Command": {"kubectl exec"}},
				},
				"response": map[string]any{
					"status_code": tt.expectedStatusCode,
					"headers":     http.Header{"Audit-Id": {"audit-id-1"}},
				},
			})
			assert.NotEmpty(t, logContext["request_id"])
			assert.NotEmpty(t, logContext["requested_at"])

			if tt.expectedPanic != "" {
				assert.Equal(t, tt.expectedPanic, logContext["panic"])
			}
		})
	}
}

func TestAuditMiddleware_FailedToRetrieveProxyConn(t *testing.T) {
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not be called")
	})

	request := httptest.NewRequest(http.MethodGet, "/api", nil)
	recorder := httptest.NewRecorder()

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	auditMiddleware(handler, logger).ServeHTTP(recorder, request)

	response := recorder.Result()
	assert.Equal(t, http.StatusInternalServerError, response.StatusCode)
	assert.Equal(t, "Internal server error\n", recorder.Body.String())

	assert.Len(t, logs.All(), 1)
	log := logs.All()[0]
	assert.Equal(t, zapcore.ErrorLevel, log.Level)
	assert.Equal(t, "Failed to retrieve proxy connection from context", log.Message)

	logContext := log.ContextMap()
	assert.Subset(t, logContext, map[string]any{
		"method":      "GET",
		"url":         "/api",
		"remote_addr": request.RemoteAddr,
	})
	assert.NotEmpty(t, logContext["request_id"])
	assert.NotEmpty(t, logContext["requested_at"])
}
