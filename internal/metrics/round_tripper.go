// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metric label names.

const labelResourceType = "resource_type"

// Resource type values.

const (
	ResourceTypeKubernetes = "kubernetes"
	ResourceTypeWebApp     = "web_app"
)

type RoundTripperMetrics struct {
	requestsTotal   *prometheus.CounterVec
	activeRequests  *prometheus.GaugeVec
	requestDuration *prometheus.HistogramVec
}

func RegisterRoundTripperMetrics(registry *prometheus.Registry) *RoundTripperMetrics {
	c := &RoundTripperMetrics{
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "api_server_requests_total",
			Help:      "Total number of requests from Gateway to HTTP server processed",
		}, []string{labelResourceType, "type", "method", "code"}),

		activeRequests: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "api_server_active_requests",
			Help:      "Number of currently active requests from Gateway to HTTP server",
		}, []string{labelResourceType, "type"}),

		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: Namespace,
				Name:      "api_server_request_duration_seconds",
				Help:      "Measures the initial HTTP request-response latency between Gateway and HTTP server in seconds. For HTTP streaming, WebSocket, and SPDY connections, this metric captures only the setup time and not the duration of the data transfer.",
				Buckets:   prometheus.DefBuckets,
			}, []string{labelResourceType, "type", "method", "code"}),
	}

	registry.MustRegister(c.requestsTotal, c.activeRequests, c.requestDuration)

	return c
}

func InstrumentRoundTripper(metrics *RoundTripperMetrics, resourceType string, next http.RoundTripper) promhttp.RoundTripperFunc {
	resourceTypeOpt := promhttp.WithLabelFromCtx(labelResourceType, func(_ context.Context) string { return resourceType })
	requestTypeOpt := promhttp.WithLabelFromCtx(labelRequestType, getRequestTypeFromContext)

	base := promhttp.InstrumentRoundTripperCounter(
		metrics.requestsTotal,
		instrumentRoundTripperInFlight(
			metrics.activeRequests,
			resourceType,
			promhttp.InstrumentRoundTripperDuration(
				metrics.requestDuration,
				next,
				resourceTypeOpt,
				requestTypeOpt,
			),
		),
		resourceTypeOpt,
		requestTypeOpt,
	)

	return func(r *http.Request) (*http.Response, error) {
		return base.RoundTrip(requestWithTypeContext(r))
	}
}

func instrumentRoundTripperInFlight(activeRequests *prometheus.GaugeVec, resourceType string, next http.RoundTripper) promhttp.RoundTripperFunc {
	return func(r *http.Request) (*http.Response, error) {
		requestType := getRequestTypeFromContext(r.Context())

		activeRequests.WithLabelValues(resourceType, requestType).Inc()
		defer activeRequests.WithLabelValues(resourceType, requestType).Dec()

		return next.RoundTrip(r)
	}
}
