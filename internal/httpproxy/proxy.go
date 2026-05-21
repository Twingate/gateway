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

	"gateway/internal/metrics"
)

type connContextKey string

const ConnContextKey connContextKey = "CONN_CONTEXT"

type Config struct {
	Handler  http.Handler
	Registry *prometheus.Registry
	Logger   *zap.Logger
}

type Proxy struct {
	httpServer *http.Server
}

func NewProxy(cfg Config) *Proxy {
	handler := metrics.HTTPMiddleware(metrics.HTTPMiddlewareConfig{
		Registry: cfg.Registry,
		Next:     auditMiddleware(cfg.Handler, cfg.Logger),
	})

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	httpServer := &http.Server{
		// G112 - Protect against Slowloris attack
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           mux,
		// add the net.Conn to the context so we can track this connection, this context
		// will be merged with and retrievable in the http.Request that is passed in to the Handler func and
		// since our custom listener provided a wrapped net.Conn (ProxyConn), its fields will be
		// available, specifically the identity information parsed from CONNECT
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, ConnContextKey, c)
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
