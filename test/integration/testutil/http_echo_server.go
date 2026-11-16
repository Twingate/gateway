// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/websocket"
)

type EchoResponse struct {
	Headers http.Header `json:"headers"`
}

// SetupHTTPEchoServer starts an HTTP server that responds with the request headers as JSON. It
// also serves an event stream that stays open until the client disconnects at /events, and a
// WebSocket that echoes each message at /ws.
func SetupHTTPEchoServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		resp := EchoResponse{
			Headers: r.Header,
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		// A comment line, so the stream opens before the first event
		_, _ = io.WriteString(w, ": open\n\n")
		_ = http.NewResponseController(w).Flush()

		<-r.Context().Done()
	})

	mux.Handle("/ws", websocket.Handler(func(conn *websocket.Conn) {
		_, _ = io.Copy(conn, conn)
	}))

	server := httptest.NewServer(mux)

	t.Cleanup(server.Close)

	return server
}
