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
)

type DBMetrics struct {
	activeSessions              *prometheus.GaugeVec
	sessionsTotal               *prometheus.CounterVec
	credentialRetrievalDuration *prometheus.HistogramVec
	upstreamConnectDuration     *prometheus.HistogramVec
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

		credentialRetrievalDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "db_credential_retrieval_duration_seconds",
			Help:      "Time taken to retrieve the credential for the upstream database in seconds",
			Buckets:   prometheus.DefBuckets,
		}, []string{labelResourceType, labelAuthType}),

		upstreamConnectDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "db_upstream_connect_duration_seconds",
			Help:      "Time taken to connect and log in to the upstream database in seconds",
			Buckets:   prometheus.DefBuckets,
		}, []string{labelResourceType}),
	}

	registry.MustRegister(m.activeSessions, m.sessionsTotal, m.credentialRetrievalDuration, m.upstreamConnectDuration)

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

func (m *DBResourceMetrics) RecordCredentialRetrieval(authType string, duration time.Duration) {
	m.metrics.credentialRetrievalDuration.WithLabelValues(m.resourceType, authType).Observe(duration.Seconds())
}

func (m *DBResourceMetrics) RecordUpstreamConnect(duration time.Duration) {
	m.metrics.upstreamConnectDuration.WithLabelValues(m.resourceType).Observe(duration.Seconds())
}

// TrackActiveSession counts a session as active until the returned function is called.
func (m *DBResourceMetrics) TrackActiveSession() func() {
	activeSessions := m.metrics.activeSessions.WithLabelValues(m.resourceType)
	activeSessions.Inc()

	return activeSessions.Dec
}
