// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package kubernetes

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/streaming/pkg/httpstream/wsstream"

	k8stransport "k8s.io/client-go/transport"

	"gateway/internal/backend/httpproxy"
	"gateway/internal/backend/kubernetes/wshijacker"
	"gateway/internal/config"
	"gateway/internal/frontend"
	"gateway/internal/metrics"
	"gateway/internal/sessionrecorder"
)

var errUpstreamTLSConfigFailed = errors.New("failed to create upstream TLS config")

type Handler struct {
	proxy            http.Handler
	sessionRecording *config.SessionRecordingConfig
}

func NewHandler(cfg Config) (*Handler, error) {
	transport, err := createTransport(cfg.bearerToken, cfg.bearerTokenFile, cfg.caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes transport: %w", err)
	}

	errorLog, _ := zap.NewStdLogAt(cfg.logger.System, zapcore.ErrorLevel)

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			conn := httpproxy.ProxyConnFromContext(r.In.Context())
			rewrite(r, conn)
		},
		Transport: metrics.InstrumentRoundTripper(cfg.roundTripperMetrics, metrics.ResourceTypeKubernetes, transport),
		ErrorLog:  errorLog,
	}

	handler := &Handler{
		proxy:            proxy,
		sessionRecording: cfg.sessionRecording,
	}

	return handler, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger := httpproxy.LoggerFromContext(r.Context())

	conn := httpproxy.ProxyConnFromContext(r.Context())

	switch {
	case wsstream.IsWebSocketRequest(r) && !shouldSkipWebSocketRequest(r):
		// Audit Websocket streaming session
		recorderFactory := func() sessionrecorder.Recorder {
			return sessionrecorder.New(logger.Session, h.sessionRecording.Segment)
		}
		wsHijacker := wshijacker.NewHijacker(r, w, conn.Claims.User.Username, recorderFactory, wshijacker.NewConn)
		h.proxy.ServeHTTP(wsHijacker, r)
	default:
		h.proxy.ServeHTTP(w, r)
	}
}

func rewrite(r *httputil.ProxyRequest, conn *frontend.ProxyConn) {
	targetURL := &url.URL{
		Scheme: "https",
		Host:   conn.GetUpstreamAddress(),
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
	switch {
	case strings.HasSuffix(r.URL.Path, "/portforward"):
		return true
	case strings.HasSuffix(r.URL.Path, "/exec"):
		// Skip file transferring from `kubectl cp`
		return isKubectlCpCommand(r.URL.Query()["command"])
	default:
		return false
	}
}

// isKubectlCpCommand reports whether command is exactly an argument list that `kubectl cp` runs
// in a container. Any other `tar` invocation is not matched because `tar` options such as
// `--checkpoint-action` and `--to-command` run arbitrary commands.
func isKubectlCpCommand(command []string) bool {
	if len(command) == 0 || command[0] != "tar" {
		return false
	}

	args := command[1:]

	// Copy from the container: tar cf - <path>
	if len(args) == 3 && slices.Equal(args[:2], []string{"cf", "-"}) {
		// A path starting with `-` is parsed by `tar` as an option.
		return !strings.HasPrefix(args[2], "-")
	}

	// Copy to the container: tar [--no-same-permissions --no-same-owner] -xmf - [-C <dir>]
	if n := len(args); n >= 2 && args[n-2] == "-C" {
		args = args[:n-2]
	}

	return slices.Equal(args, []string{"-xmf", "-"}) ||
		slices.Equal(args, []string{"--no-same-permissions", "--no-same-owner", "-xmf", "-"})
}
