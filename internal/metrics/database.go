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

// DBOutcome is how the setup of a database session ended.
type DBOutcome string

const (
	DBOutcomeSuccess              DBOutcome = "success"
	DBOutcomeFailure              DBOutcome = "failure"
	DBOutcomeClientError          DBOutcome = "client_error"
	DBOutcomeCredentialError      DBOutcome = "credential_error" // #nosec G101 -- metric label value, not a credential
	DBOutcomeUpstreamConnectError DBOutcome = "upstream_connect_error"
)

type DBMetrics struct {
	activeSessions              *prometheus.GaugeVec
	sessionsTotal               *prometheus.CounterVec
	cancelTotal                 *prometheus.CounterVec
	credentialRetrievalDuration prometheus.ObserverVec
	upstreamConnectDuration     prometheus.ObserverVec
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

		cancelTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "db_cancel_total",
			Help:      "Total number of query cancel requests forwarded to the database by outcome",
		}, []string{labelResourceType, labelOutcome}),

		credentialRetrievalDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "db_credential_retrieval_duration_seconds",
			Help:      "Time taken to retrieve the credential for the upstream database in seconds",
			Buckets:   prometheus.DefBuckets,
		}, []string{labelResourceType, labelAuthType, labelOutcome}),

		upstreamConnectDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "db_upstream_connect_duration_seconds",
			Help:      "Time taken to connect and log in to the upstream database in seconds",
			Buckets:   prometheus.DefBuckets,
		}, []string{labelResourceType, labelOutcome}),
	}

	registry.MustRegister(m.activeSessions, m.sessionsTotal, m.cancelTotal, m.credentialRetrievalDuration, m.upstreamConnectDuration)

	return m
}

// WithResourceType returns the metrics of one database resource type, with the resource_type label
// already set. Only the returned metrics can record.
func (m *DBMetrics) WithResourceType(resourceType ResourceType) *DBMetrics {
	labels := prometheus.Labels{labelResourceType: string(resourceType)}

	return &DBMetrics{
		activeSessions:              m.activeSessions.MustCurryWith(labels),
		sessionsTotal:               m.sessionsTotal.MustCurryWith(labels),
		cancelTotal:                 m.cancelTotal.MustCurryWith(labels),
		credentialRetrievalDuration: m.credentialRetrievalDuration.MustCurryWith(labels),
		upstreamConnectDuration:     m.upstreamConnectDuration.MustCurryWith(labels),
	}
}

func (m *DBMetrics) RecordSession(outcome DBOutcome) {
	m.sessionsTotal.WithLabelValues(string(outcome)).Inc()
}

func (m *DBMetrics) RecordCancel(outcome DBOutcome) {
	m.cancelTotal.WithLabelValues(string(outcome)).Inc()
}

func (m *DBMetrics) RecordCredentialRetrieval(authType string, outcome DBOutcome, duration time.Duration) {
	m.credentialRetrievalDuration.WithLabelValues(authType, string(outcome)).Observe(duration.Seconds())
}

func (m *DBMetrics) RecordUpstreamConnect(outcome DBOutcome, duration time.Duration) {
	m.upstreamConnectDuration.WithLabelValues(string(outcome)).Observe(duration.Seconds())
}

// TrackActiveSession counts a session as active until the returned function is called.
func (m *DBMetrics) TrackActiveSession() func() {
	activeSessions := m.activeSessions.WithLabelValues()
	activeSessions.Inc()

	return activeSessions.Dec
}
