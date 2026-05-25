// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httphandler

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"k8s.io/streaming/pkg/httpstream/wsstream"

	k8stransport "k8s.io/client-go/transport"

	"gateway/internal/config"
	"gateway/internal/connect"
	"gateway/internal/httphandler/wshijacker"
	"gateway/internal/httpproxy"
	"gateway/internal/metrics"
	"gateway/internal/sessionrecorder"
)

var errUpstreamTLSConfigFailed = errors.New("failed to create upstream TLS config")

type KubernetesHandler struct {
	proxy    http.Handler
	auditLog *config.AuditLogConfig
}

func NewKubernetesHandler(cfg Config) (*KubernetesHandler, error) {
	transport, err := createTransport(cfg.bearerToken, cfg.bearerTokenFile, cfg.caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes transport: %w", err)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			conn, ok := r.In.Context().Value(httpproxy.ConnContextKey).(*connect.ProxyConn)
			if !ok {
				cfg.logger.Error("Failed to retrieve net.Conn from context")

				return
			}

			rewrite(r, conn)
		},
		Transport: metrics.InstrumentRoundTripper(cfg.roundTripperCollectors, transport),
	}

	handler := &KubernetesHandler{
		proxy:    proxy,
		auditLog: cfg.auditLog,
	}

	return handler, nil
}

func (h *KubernetesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auditLogger := httpproxy.AuditLoggerFromContext(r.Context())

	conn, ok := r.Context().Value(httpproxy.ConnContextKey).(*connect.ProxyConn)
	if !ok {
		auditLogger.Error("Failed to retrieve proxy connection from context")
		http.Error(w, "Internal server error", http.StatusInternalServerError)

		return
	}

	switch {
	case wsstream.IsWebSocketRequest(r) && !shouldSkipWebSocketRequest(r):
		// Audit Websocket streaming session
		recorderFactory := func() sessionrecorder.Recorder {
			return sessionrecorder.NewRecorder(
				auditLogger,
				sessionrecorder.WithFlushSizeThreshold(h.auditLog.FlushSizeThreshold),
				sessionrecorder.WithFlushInterval(h.auditLog.FlushInterval),
			)
		}
		wsHijacker := wshijacker.NewHijacker(r, w, conn.Claims.User.Username, recorderFactory, wshijacker.NewConn)
		h.proxy.ServeHTTP(wsHijacker, r)
	default:
		h.proxy.ServeHTTP(w, r)
	}
}

func rewrite(r *httputil.ProxyRequest, conn *connect.ProxyConn) {
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
}

func createTransport(bearerToken, bearerTokenFile, caFile string) (http.RoundTripper, error) {
	// create TLS configuration for upstream
	caCert, err := os.ReadFile(caFile) //nolint:gosec // The CA file is provided by the user
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, errUpstreamTLSConfigFailed
	}

	transport, err := k8stransport.NewBearerAuthWithRefreshRoundTripper(
		bearerToken,
		bearerTokenFile,
		&http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    caCertPool,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create bearer auth round tripper: %w", err)
	}

	return transport, nil
}

func shouldSkipWebSocketRequest(r *http.Request) bool {
	// Skip tunneling requests (e.g. `kubectl proxy`)
	return wsstream.IsWebSocketRequestWithTunnelingProtocol(r) ||
		// Skip file transferring from `kubectl cp`
		r.Header.Get("Kubectl-Command") == "kubectl cp" ||
		// Skip executing `tar` command
		r.URL.Query().Get("command") == "tar"
}
