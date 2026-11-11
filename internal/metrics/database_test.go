// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"gateway/internal/metrics/testutil"
)

func TestDBMetrics(t *testing.T) {
	testRegistry := prometheus.NewRegistry()

	dbMetrics := RegisterDBMetrics(testRegistry)
	pgMetrics := dbMetrics.WithResourceType(ResourceTypePostgreSQL)

	pgMetrics.RecordSession(DBSessionOutcomeSuccess)
	pgMetrics.RecordUpstreamLogin("password", time.Second)
	sessionEnded := pgMetrics.TrackActiveSession()

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	labelsByMetric := testutil.ExtractLabelsFromMetrics(metricFamilies)
	expectedLabels := map[string]map[string]string{
		"twingate_gateway_db_active_sessions": {
			"resource_type": "postgresql",
		},
		"twingate_gateway_db_sessions_total": {
			"resource_type": "postgresql",
			"outcome":       "success",
		},
		"twingate_gateway_db_upstream_login_duration_seconds": {
			"resource_type": "postgresql",
			"auth_type":     "password",
		},
	}
	assert.Equal(t, expectedLabels, labelsByMetric)

	assert.InDelta(t, 1, promtestutil.ToFloat64(dbMetrics.sessionsTotal), 0)
	assert.InDelta(t, 1, promtestutil.ToFloat64(dbMetrics.activeSessions), 0)

	histogram := testutil.GetHistogram("twingate_gateway_db_upstream_login_duration_seconds", metricFamilies)
	require.NotNil(t, histogram)
	assert.Equal(t, uint64(1), histogram.GetSampleCount())
	assert.InDelta(t, 1, histogram.GetSampleSum(), 0)

	sessionEnded()

	assert.Zero(t, promtestutil.ToFloat64(dbMetrics.activeSessions))
}
