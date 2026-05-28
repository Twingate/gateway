// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"context"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/streaming/pkg/httpstream"
	"k8s.io/streaming/pkg/httpstream/spdy"
	"k8s.io/streaming/pkg/httpstream/wsstream"
)

// Metric label names.
const (
	labelRequestType = "type"
)

// Request type values.
const (
	requestTypeHTTP      = "http"
	requestTypeWebsocket = "websocket"
	requestTypeSPDY      = "spdy"
	requestTypeUnknown   = "unknown"
)

type HTTPMiddlewareConfig struct {
	Registry *prometheus.Registry
	Next     http.Handler
}

type contextKey struct{}

func HTTPMiddleware(config HTTPMiddlewareConfig) http.HandlerFunc {
	requestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "http_requests_total",
		Help:      "Total number of HTTP requests processed",
	}, []string{"type", "method", "code"})

	activeRequests := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "http_active_requests",
		Help:      "Number of currently active HTTP requests",
	}, []string{"type"})

	requestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "http_request_duration_seconds",
			Help:      "Latencies of HTTP requests in seconds",
			Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
		}, []string{"type", "method", "code"})

	requestSizeBytes := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "http_request_size_bytes",
		Help:      "Size of incoming HTTP request in bytes",
		Buckets:   prometheus.ExponentialBuckets(100, 10, 6),
	}, []string{"type", "method", "code"})

	responseSizeBytes := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "http_response_size_bytes",
		Help:      "Size of outgoing HTTP response in bytes",
		Buckets:   prometheus.ExponentialBuckets(100, 10, 6),
	}, []string{"type", "method", "code"},
	)

	config.Registry.MustRegister(requestsTotal, activeRequests, requestDuration, requestSizeBytes, responseSizeBytes)

	opts := promhttp.WithLabelFromCtx(labelRequestType, getRequestTypeFromContext)

	base := promhttp.InstrumentHandlerCounter(
		requestsTotal,
		instrumentHandlerInFlight(activeRequests,
			promhttp.InstrumentHandlerDuration(
				requestDuration,
				promhttp.InstrumentHandlerRequestSize(
					requestSizeBytes,
					promhttp.InstrumentHandlerResponseSize(
						responseSizeBytes,
						config.Next,
						opts,
					),
					opts,
				),
				opts,
			),
		),
		opts,
	)

	return func(w http.ResponseWriter, r *http.Request) {
		base.ServeHTTP(w, requestWithTypeContext(r))
	}
}

func instrumentHandlerInFlight(activeRequests *prometheus.GaugeVec, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestType := getRequestTypeFromContext(r.Context())

		activeRequests.WithLabelValues(requestType).Inc()
		defer activeRequests.WithLabelValues(requestType).Dec()

		next.ServeHTTP(w, r)
	})
}

func getRequestTypeFromContext(ctx context.Context) string {
	if value, ok := ctx.Value(contextKey{}).(string); ok {
		return value
	}

	return requestTypeUnknown
}

func isSpdyRequest(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get(httpstream.HeaderUpgrade), spdy.HeaderSpdy31) {
		return false
	}

	return httpstream.IsUpgradeRequest(r)
}

func requestWithTypeContext(r *http.Request) *http.Request {
	ctx := r.Context()

	switch {
	case isSpdyRequest(r):
		ctx = context.WithValue(ctx, contextKey{}, requestTypeSPDY)
	case wsstream.IsWebSocketRequest(r):
		ctx = context.WithValue(ctx, contextKey{}, requestTypeWebsocket)
	default:
		ctx = context.WithValue(ctx, contextKey{}, requestTypeHTTP)
	}

	return r.WithContext(ctx)
}
