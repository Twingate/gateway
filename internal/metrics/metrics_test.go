// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestInitMetricCollectors(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	registerCoreMetrics(testRegistry)

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	// Note that this list only contain a subset of Go and process metrics.
	// We want to make sure that the Go and process collectors are registered.
	expectedMetrics := []string{
		// Go Metric
		"go_gc_duration_seconds",
		// Process Metric
		"process_cpu_seconds_total",
	}

	registeredMetrics := make([]string, len(metricFamilies))
	for i, mf := range metricFamilies {
		registeredMetrics[i] = mf.GetName()
	}

	assert.Subset(t, registeredMetrics, expectedMetrics)
}

func TestNewServer_Pprof(t *testing.T) {
	tests := []struct {
		name        string
		enablePprof bool
		wantStatus  int
	}{
		{name: "pprof disabled", enablePprof: false, wantStatus: http.StatusNotFound},
		{name: "pprof enabled", enablePprof: true, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(Config{
				Registry:    prometheus.NewRegistry(),
				Logger:      zap.NewNop(),
				EnablePprof: tt.enablePprof,
			})

			for _, path := range []string{"/debug/pprof/", "/debug/pprof/heap"} {
				recorder := httptest.NewRecorder()
				server.server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))

				assert.Equal(t, tt.wantStatus, recorder.Code, path)
			}

			recorder := httptest.NewRecorder()
			server.server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			assert.Equal(t, http.StatusOK, recorder.Code, "/metrics")
		})
	}
}
