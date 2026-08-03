// Copyright (c) Twingate Inc.

// SPDX-License-Identifier: MPL-2.0

package main

import (
	"errors"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// webSSHDir holds the page and the artifacts produced by `make webssh`.
const webSSHDir = "./tools/webssh"

type webSSHServer struct {
	server  *http.Server
	address string
}

// startWebSSHServer stands in for the Twingate Client, which is where the page would be hosted in
// production: it must share an origin scheme with the WebSocket, and an https:// page cannot open
// a ws:// socket.
func startWebSSHServer(logger *zap.Logger, sshClientAddress string) *webSSHServer {
	if _, err := os.Stat(filepath.Join(webSSHDir, "main.wasm")); err != nil {
		logger.Warn("Web SSH client is not built, run `make webssh`", zap.Error(err))
	}

	page, err := template.ParseFiles(filepath.Join(webSSHDir, "index.html"))
	if err != nil {
		logger.Fatal("Failed to parse Web SSH page", zap.Error(err))
	}

	assets := http.FileServer(http.Dir(webSSHDir))

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			assets.ServeHTTP(w, r)

			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		data := struct {
			WebSocketURL string
			Username     string
		}{
			WebSocketURL: "ws://" + sshClientAddress,
			Username:     sshUsername,
		}

		if err := page.Execute(w, data); err != nil {
			logger.Error("Failed to render Web SSH page", zap.Error(err))
		}
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		logger.Fatal("Failed to create Web SSH server listener", zap.Error(err))
	}

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Web SSH server error", zap.Error(err))
		}
	}()

	return &webSSHServer{server: server, address: listener.Addr().String()}
}
