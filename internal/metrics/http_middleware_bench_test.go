// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func newBenchRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "kubectl/v1.37.0 (darwin/arm64) kubernetes/abcdef")

	return req
}

func BenchmarkHTTPMiddleware(b *testing.B) {
	handler := HTTPMiddleware(
		RegisterHTTPMetrics(prometheus.NewRegistry()),
		ResourceTypeKubernetes,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	req := newBenchRequest()

	b.ReportAllocs()

	for b.Loop() {
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
}

func BenchmarkInstrumentRoundTripper(b *testing.B) {
	rt := InstrumentRoundTripper(
		RegisterRoundTripperMetrics(prometheus.NewRegistry()),
		ResourceTypeKubernetes,
		promhttp.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
			// promhttp reads the labels from the context of the response's request.
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
		}),
	)
	req := newBenchRequest()

	b.ReportAllocs()

	for b.Loop() {
		resp, err := rt.RoundTrip(req)
		if err != nil {
			b.Fatal(err)
		}

		_ = resp.Body.Close()
	}
}
