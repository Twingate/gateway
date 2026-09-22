// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package frontend

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"gateway/internal/metrics"
)

const (
	ConnCategoryUnknown = "unknown"
	ConnCategoryProxy   = "proxy"
	ConnCategoryHealth  = "health"
)

type ProxyConnMetrics struct {
	activeConn   prometheus.Gauge
	connTotal    *prometheus.CounterVec
	connDuration *prometheus.HistogramVec

	connectTotal    *prometheus.CounterVec
	connectDuration *prometheus.HistogramVec
}

func CreateProxyConnMetrics(registry *prometheus.Registry) *ProxyConnMetrics {
	activeConn := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metrics.Namespace,
		Name:      "active_tcp_connections",
		Help:      "Number of currently active client TCP connections",
	})
	connTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connections_total",
		Help:      "Total number of client TCP connections processed",
	}, []string{"connection_category"})
	connDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Name:      "tcp_connection_duration_seconds",
		Help:      "Duration of client TCP connections in seconds",
		Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
	}, []string{"connection_category"})

	connectTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "client_authentication_total",
		Help:      "Total number of HTTP CONNECT authentication attempts",
	}, []string{"code"})
	connectDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Name:      "client_connection_duration_seconds",
		Help:      "Duration of HTTP CONNECT authentication attempt in seconds",
		Buckets:   prometheus.DefBuckets,
	}, []string{"code"})

	registry.MustRegister(activeConn, connTotal, connDuration, connectTotal, connectDuration)

	return &ProxyConnMetrics{
		activeConn:      activeConn,
		connTotal:       connTotal,
		connDuration:    connDuration,
		connectTotal:    connectTotal,
		connectDuration: connectDuration,
	}
}

type ProxyConnMetricsTracker struct {
	metrics      *ProxyConnMetrics
	start        time.Time
	ConnCategory string
}

func NewProxyConnMetricsTracker(connCategory string, proxyConnMetrics *ProxyConnMetrics) *ProxyConnMetricsTracker {
	proxyConnMetrics.activeConn.Inc()

	return &ProxyConnMetricsTracker{
		metrics:      proxyConnMetrics,
		start:        time.Now(),
		ConnCategory: connCategory,
	}
}

func (t *ProxyConnMetricsTracker) RecordConnMetrics() {
	t.metrics.activeConn.Dec()
	t.metrics.connTotal.WithLabelValues(t.ConnCategory).Inc()
	t.metrics.connDuration.WithLabelValues(t.ConnCategory).Observe(time.Since(t.start).Seconds())
}

func (t *ProxyConnMetricsTracker) RecordConnectMetrics(code int) {
	codeStr := strconv.Itoa(code)
	t.metrics.connectDuration.WithLabelValues(codeStr).Observe(time.Since(t.start).Seconds())
	t.metrics.connectTotal.WithLabelValues(codeStr).Inc()
}
