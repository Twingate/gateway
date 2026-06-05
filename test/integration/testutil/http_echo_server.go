// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type EchoResponse struct {
	Headers http.Header `json:"headers"`
}

func SetupHTTPEchoServer(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := EchoResponse{
			Headers: r.Header,
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))

	t.Cleanup(server.Close)

	return server
}
