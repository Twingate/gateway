// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gateway/internal/metrics/testutil"
)

func TestInstrumentRoundTripper(t *testing.T) {
	testRegistry := prometheus.NewRegistry()

	collectors := RegisterRoundTripperMetrics(testRegistry)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	transport := InstrumentRoundTripper(collectors, promhttp.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
	}))

	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	labelsByMetric := testutil.ExtractLabelsFromMetrics(metricFamilies)
	expectedLabels := map[string]map[string]string{
		"twingate_gateway_api_server_requests_total": {
			"type":   "http",
			"method": "get",
			"code":   "200",
		},
		"twingate_gateway_api_server_active_requests": {
			"type": "http",
		},
		"twingate_gateway_api_server_request_duration_seconds": {
			"type":   "http",
			"method": "get",
			"code":   "200",
		},
	}
	assert.Equal(t, expectedLabels, labelsByMetric)
}

func TestInstrumentRoundTripper_MultipleTransports(t *testing.T) {
	testRegistry := prometheus.NewRegistry()

	collectors := RegisterRoundTripperMetrics(testRegistry)

	mockTransport := promhttp.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
	})

	// Instrumenting multiple transports should not panic
	transport1 := InstrumentRoundTripper(collectors, mockTransport)
	transport2 := InstrumentRoundTripper(collectors, mockTransport)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	resp1, err := transport1.RoundTrip(req)
	require.NoError(t, err)

	defer resp1.Body.Close()

	resp2, err := transport2.RoundTrip(req)
	require.NoError(t, err)

	defer resp2.Body.Close()
}
