// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"gateway/internal/connect"
	"gateway/internal/metrics"
)

type ConnContextKey struct{}

func ProxyConnFromContext(ctx context.Context) *connect.ProxyConn {
	conn, ok := ctx.Value(ConnContextKey{}).(*connect.ProxyConn)
	if !ok {
		panic("proxy connection not found in context: caller must use httpproxy server")
	}

	return conn
}

type Config struct {
	Handlers map[string]http.Handler
	Registry *prometheus.Registry
	Logger   *zap.Logger
}

type Proxy struct {
	httpServer *http.Server
}

func newResourceRouter(handlers map[string]http.Handler, logger *zap.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := ProxyConnFromContext(r.Context())
		resourceType := conn.GATClaims().Resource.Type

		handler, exists := handlers[resourceType]
		if !exists {
			logger.Error("No handler for resource type", zap.String("type", resourceType))
			http.Error(w, "unsupported resource type", http.StatusNotFound)

			return
		}

		handler.ServeHTTP(w, r)
	})
}

func NewProxy(cfg Config) *Proxy {
	router := newResourceRouter(cfg.Handlers, cfg.Logger)
	handler := metrics.HTTPMiddleware(metrics.HTTPMiddlewareConfig{
		Registry: cfg.Registry,
		Next: auditMiddleware(auditMiddlewareConfig{
			next:   router,
			logger: cfg.Logger,
		}),
	})

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	httpServer := &http.Server{
		// G112 - Protect against Slowloris attack
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           mux,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, ConnContextKey{}, c)
		},
	}

	return &Proxy{
		httpServer: httpServer,
	}
}

func (p *Proxy) Start(listener net.Listener) error {
	return p.httpServer.Serve(listener)
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	return p.httpServer.Shutdown(ctx)
}
