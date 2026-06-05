// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"context"
	"net"
	"net/http"
	"time"

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
	Handler      http.Handler
	Metrics      *metrics.HTTPMetrics
	Logger       *zap.Logger
	ResourceType metrics.ResourceType
}

type Proxy struct {
	httpServer *http.Server
}

func NewProxy(cfg Config) *Proxy {
	handler := metrics.HTTPMiddleware(cfg.Metrics, cfg.ResourceType, auditMiddleware(auditMiddlewareConfig{
		next:   cfg.Handler,
		logger: cfg.Logger,
	}))

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
