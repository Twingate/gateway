// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"gateway/internal/frontend"
	"gateway/internal/logging"
	"gateway/internal/metrics"
)

type ConnContextKey struct{}

func ProxyConnFromContext(ctx context.Context) *frontend.ProxyConn {
	conn, ok := ctx.Value(ConnContextKey{}).(*frontend.ProxyConn)
	if !ok {
		panic("proxy connection not found in context: caller must use httpproxy server")
	}

	return conn
}

type Config struct {
	Handler      http.Handler
	Metrics      *metrics.HTTPMetrics
	Logger       logging.Logger
	ResourceType metrics.ResourceType
}

type Proxy struct {
	httpServer *http.Server
}

func NewProxy(cfg Config) *Proxy {
	mux := http.NewServeMux()
	mux.Handle("/", cfg.Handler)

	handler := metrics.HTTPMiddleware(cfg.Metrics, cfg.ResourceType, auditMiddleware(auditMiddlewareConfig{
		next:   misdirectedRequestMiddleware(mux),
		logger: cfg.Logger,
	}))

	errorLog, _ := zap.NewStdLogAt(cfg.Logger.System, zapcore.ErrorLevel)

	httpServer := &http.Server{
		// G112 - Protect against Slowloris attack
		ReadHeaderTimeout: 5 * time.Second,
		// Long enough that the client usually closes an idle connection first, since a new connection
		// costs the client a CONNECT, GAT and Proof-of-Possession validation, and a TLS handshake.
		IdleTimeout: 5 * time.Minute,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: 30 * time.Second,
		},
		Handler:  handler,
		ErrorLog: errorLog,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tlsConn, ok := c.(*tls.Conn); ok {
				c = tlsConn.NetConn()
			}

			return context.WithValue(ctx, ConnContextKey{}, c)
		},
	}

	return &Proxy{
		httpServer: httpServer,
	}
}

func (p *Proxy) Start(listener net.Listener) error {
	return p.httpServer.Serve(&tlsUpgradeListener{Listener: listener})
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	return p.httpServer.Shutdown(ctx)
}

// ALPN protocol IDs, see
// https://www.iana.org/assignments/tls-extensiontype-values#alpn-protocol-ids.
const (
	alpnHTTP2  = "h2"
	alpnHTTP11 = "http/1.1"
)

// tlsUpgradeListener wraps each accepted connection whose GAT requires TLS in a TLS server
// connection. The handshake runs on first use, in the http.Server goroutine serving the
// connection, so Accept does not block on the protocol client.
type tlsUpgradeListener struct {
	net.Listener
}

func (l *tlsUpgradeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	if proxyConn, ok := conn.(*frontend.ProxyConn); ok && proxyConn.GATClaims().ShouldUpgradeTLS() {
		tlsConfig := proxyConn.TLSConfig.Clone()
		tlsConfig.NextProtos = []string{alpnHTTP2, alpnHTTP11}

		return tls.Server(conn, tlsConfig), nil
	}

	return conn, nil
}
