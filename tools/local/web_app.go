// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
)

type echoServer struct {
	server  *http.Server
	address string
}

func startEchoWebAppServer(logger *zap.Logger) *echoServer {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		resp := struct {
			Method  string      `json:"method"`
			Path    string      `json:"path"`
			Headers http.Header `json:"headers"`
		}{
			Method:  r.Method,
			Path:    r.URL.Path,
			Headers: r.Header,
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Error("Failed to encode response", zap.Error(err))
		}
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		logger.Fatal("Failed to create Web app echo server listener", zap.Error(err))
	}

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Web app echo server error", zap.Error(err))
		}
	}()

	return &echoServer{server: server, address: listener.Addr().String()}
}
