// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httphandler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"k8s.io/streaming/pkg/httpstream/wsstream"

	k8stransport "k8s.io/client-go/transport"

	"gateway/internal/connect"
	"gateway/internal/httphandler/wshijacker"
	"gateway/internal/metrics"
	"gateway/internal/sessionrecorder"
)

type connContextKey string

const ConnContextKey connContextKey = "CONN_CONTEXT"

var errUpstreamTLSConfigFailed = errors.New("failed to create upstream TLS config")

type Proxy struct {
	config     Config
	httpServer *http.Server
	proxy      *httputil.ReverseProxy
}

func NewProxy(cfg Config) (*Proxy, error) {
	logger := cfg.logger

	// create TLS configuration for upstream
	caCert, err := os.ReadFile(cfg.caFile)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, errUpstreamTLSConfigFailed
	}

	upstreamTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    caCertPool,
	}

	transport, err := k8stransport.NewBearerAuthWithRefreshRoundTripper(
		cfg.bearerToken,
		cfg.bearerTokenFile,
		&http.Transport{
			TLSClientConfig: upstreamTLSConfig,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create bearer auth round tripper: %w", err)
	}

	httpProxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			conn, ok := r.In.Context().Value(ConnContextKey).(*connect.ProxyConn)
			if !ok {
				logger.Error("Failed to retrieve net.Conn from context")

				return
			}

			targetURL := &url.URL{
				Scheme: "https",
				Host:   conn.GetAddress(),
			}
			r.SetURL(targetURL)

			// As a precaution, remove existing k8s related headers from downstream.
			r.Out.Header.Del("Authorization")
			r.Out.Header.Del("Impersonate-User")
			r.Out.Header.Del("Impersonate-Group")
			r.Out.Header.Del("Impersonate-Uid")

			for k := range r.Out.Header {
				if strings.HasPrefix(k, "Impersonate-Extra-") {
					r.Out.Header.Del(k)
				}
			}

			// Set impersonation header to impersonate the user
			// identified from downstream.
			r.Out.Header.Set("Impersonate-User", conn.Claims.User.Username)

			for _, group := range conn.Claims.User.Groups {
				r.Out.Header.Add("Impersonate-Group", group)
			}
		},
		Transport: metrics.RoundTripper(metrics.RoundTripperConfig{
			Registry: cfg.registry,
			Next:     transport,
		}),
	}

	mux := http.NewServeMux()
	httpServer := &http.Server{
		// G112 - Protect against Slowloris attack
		ReadHeaderTimeout: 5 * time.Second,

		Handler: mux,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// add the net.Conn to the context so we can track this connection, this context
			// will be merged with and retrievable in the http.Request that is passed in to the Handler func and
			// since our custom listener provided a wrapped net.Conn (ProxyConn), its fields will be
			// available, specifically the identity information parsed from CONNECT
			return context.WithValue(ctx, ConnContextKey, c)
		},
	}

	p := &Proxy{
		httpServer: httpServer,
		proxy:      httpProxy,
		config:     cfg,
	}
	handler := metrics.HTTPMiddleware(metrics.HTTPMiddlewareConfig{
		Registry: cfg.registry,
		Next: auditMiddleware(auditMiddlewareConfig{
			next:   p.serveHTTP,
			logger: logger,
		}),
	})
	mux.Handle("/", handler)

	return p, nil
}

func (p *Proxy) Start(listener net.Listener) error {
	return p.httpServer.Serve(listener)
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	return p.httpServer.Shutdown(ctx)
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request, conn *connect.ProxyConn, auditLogger *zap.Logger) {
	switch {
	case wsstream.IsWebSocketRequest(r) && !shouldSkipWebSocketRequest(r):
		// Audit Websocket streaming session
		recorderFactory := func() sessionrecorder.Recorder {
			return sessionrecorder.NewRecorder(
				auditLogger,
				sessionrecorder.WithFlushSizeThreshold(p.config.auditLog.FlushSizeThreshold),
				sessionrecorder.WithFlushInterval(p.config.auditLog.FlushInterval),
			)
		}
		wsHijacker := wshijacker.NewHijacker(r, w, conn.Claims.User.Username, recorderFactory, wshijacker.NewConn)
		p.proxy.ServeHTTP(wsHijacker, r)
	default:
		p.proxy.ServeHTTP(w, r)
	}
}

func shouldSkipWebSocketRequest(r *http.Request) bool {
	// Skip tunneling requests (e.g. `kubectl proxy`)
	return wsstream.IsWebSocketRequestWithTunnelingProtocol(r) ||
		// Skip file transferring from `kubectl cp`
		r.Header.Get("Kubectl-Command") == "kubectl cp" ||
		// Skip executing `tar` command
		r.URL.Query().Get("command") == "tar"
}
