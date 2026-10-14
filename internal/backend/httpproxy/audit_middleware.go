// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"gateway/internal/logging"
)

var (
	errFailedToHijack = errors.New("failed to hijack")
)

// Audit log field names.
const fieldHeaders = "headers"

type responseWriter struct {
	http.ResponseWriter

	headerWritten bool
	statusCode    int
	headers       http.Header
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.headerWritten = true
	rw.statusCode = code
	rw.headers = rw.Header().Clone()
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(p []byte) (int, error) {
	if !rw.headerWritten {
		// Mirror ResponseWriter.Write behavior by setting 200 status code
		// if no header has been written yet.
		rw.WriteHeader(http.StatusOK)
	}

	return rw.ResponseWriter.Write(p)
}

func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := rw.ResponseWriter.(http.Hijacker); ok {
		conn, brw, err := hijacker.Hijack()
		if err == nil {
			// If the connection is hijacked, the caller will write the response headers and body.
			// We assume it would happen successfully and set the status code to 101.
			rw.headerWritten = true
			rw.statusCode = http.StatusSwitchingProtocols
			rw.headers = rw.Header().Clone()
		}

		return conn, brw, err
	}

	return nil, nil, errFailedToHijack
}

// Compile-time checks that responseWriter implements http.Flusher and http.Hijacker.
var _ http.Flusher = &responseWriter{}  // Support HTTP streaming
var _ http.Hijacker = &responseWriter{} // Support WebSocket streaming

type LoggerKey struct{}

func LoggerFromContext(ctx context.Context) logging.Logger {
	logger, ok := ctx.Value(LoggerKey{}).(logging.Logger)
	if !ok {
		panic("logger not found in context: caller must use httpproxy server")
	}

	return logger
}

type auditMiddlewareConfig struct {
	next   http.Handler
	logger logging.Logger
}

func auditMiddleware(config auditMiddlewareConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := ProxyConnFromContext(r.Context())

		fields := []zap.Field{
			zap.String("request_id", uuid.New().String()),
			zap.Time("requested_at", time.Now()),
			zap.String("method", r.Method),
			zap.String("url", r.URL.String()),
			zap.String("remote_addr", r.RemoteAddr),
			zap.Object("user", conn.Claims.User),
			zap.String("conn_id", conn.ID),
		}
		logger := config.logger
		logger.Audit = logger.Audit.With(fields...)
		// Session recordings share the request_id and connection fields with the audit log, so a
		// recording can be tied back to the request and user that started it.
		logger.Session = logger.Session.With(fields...)

		rw := &responseWriter{ResponseWriter: w}

		defer func() {
			recovered := recover()

			// Check if there was a panic. `http.ErrAbortHandler` is considered
			// okay e.g. client closes connection during HTTP streaming.
			if recovered != nil && recovered != http.ErrAbortHandler { //nolint:err113,errorlint
				logger.Audit.Error("API request failed",
					zap.Any("request", map[string]any{
						fieldHeaders: r.Header,
					}),
					zap.Any("response", map[string]any{
						"status_code": rw.statusCode,
						fieldHeaders:  rw.headers,
					}),
					zap.Any("panic", recovered),
				)
			} else {
				logger.Audit.Info("API request completed",
					zap.Any("request", map[string]any{
						fieldHeaders: r.Header,
					}),
					zap.Any("response", map[string]any{
						"status_code": rw.statusCode,
						fieldHeaders:  rw.headers,
					}),
				)
			}

			if recovered != nil {
				// Re-panic to let others handle it
				panic(recovered)
			}
		}()

		ctx := context.WithValue(r.Context(), LoggerKey{}, logger)
		config.next.ServeHTTP(rw, r.WithContext(ctx))
	})
}
