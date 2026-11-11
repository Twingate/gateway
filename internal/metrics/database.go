// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metric label names.
const (
	labelOutcome  = "outcome"
	labelAuthType = "auth_type"
)

// DBSessionOutcome is how the setup of a database session ended.
type DBSessionOutcome string

const (
	DBSessionOutcomeSuccess              DBSessionOutcome = "success"
	DBSessionOutcomeClientError          DBSessionOutcome = "client_error"
	DBSessionOutcomeCredentialError      DBSessionOutcome = "credential_error" // #nosec G101 -- metric label value, not a credential
	DBSessionOutcomeUpstreamConnectError DBSessionOutcome = "upstream_connect_error"
	DBSessionOutcomeUpstreamLoginError   DBSessionOutcome = "upstream_login_error"
)

type DBMetrics struct {
	activeSessions        *prometheus.GaugeVec
	sessionsTotal         *prometheus.CounterVec
	upstreamLoginDuration *prometheus.HistogramVec
}

func RegisterDBMetrics(registry *prometheus.Registry) *DBMetrics {
	m := &DBMetrics{
		activeSessions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "db_active_sessions",
			Help:      "Number of database sessions currently being relayed",
		}, []string{labelResourceType}),

		sessionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "db_sessions_total",
			Help:      "Total number of database connection attempts by outcome",
		}, []string{labelResourceType, labelOutcome}),

		upstreamLoginDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "db_upstream_login_duration_seconds",
			Help:      "Time taken to log in to the upstream database in seconds",
			Buckets:   prometheus.DefBuckets,
		}, []string{labelResourceType, labelAuthType}),
	}

	registry.MustRegister(m.activeSessions, m.sessionsTotal, m.upstreamLoginDuration)

	return m
}

// WithResourceType returns the metrics of one database resource type.
func (m *DBMetrics) WithResourceType(resourceType ResourceType) *DBResourceMetrics {
	return &DBResourceMetrics{metrics: m, resourceType: string(resourceType)}
}

// DBResourceMetrics records the database metrics of one resource type.
type DBResourceMetrics struct {
	metrics      *DBMetrics
	resourceType string
}

func (m *DBResourceMetrics) RecordSession(outcome DBSessionOutcome) {
	m.metrics.sessionsTotal.WithLabelValues(m.resourceType, string(outcome)).Inc()
}

func (m *DBResourceMetrics) RecordUpstreamLogin(authType string, duration time.Duration) {
	m.metrics.upstreamLoginDuration.WithLabelValues(m.resourceType, authType).Observe(duration.Seconds())
}

// TrackActiveSession counts a session as active until the returned function is called.
func (m *DBResourceMetrics) TrackActiveSession() func() {
	activeSessions := m.metrics.activeSessions.WithLabelValues(m.resourceType)
	activeSessions.Inc()

	return activeSessions.Dec
}
