// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"context"
	"net"
	"net/http"
	"net/http/pprof" //nolint:gosec // G108: handlers are registered on the metrics mux only when pprof is enabled
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const Namespace = "twingate_gateway"

type Config struct {
	Registry *prometheus.Registry
	Logger   *zap.Logger
	// EnablePprof serves the net/http/pprof profiling endpoints under /debug/pprof/.
	EnablePprof bool
}

type Server struct {
	server *http.Server
}

func NewServer(config Config) *Server {
	registerCoreMetrics(config.Registry)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.InstrumentMetricHandler(
		config.Registry,
		promhttp.HandlerFor(config.Registry, promhttp.HandlerOpts{Registry: config.Registry}),
	))

	if config.EnablePprof {
		registerPprofHandlers(mux)
	}

	errorLog, _ := zap.NewStdLogAt(config.Logger, zapcore.ErrorLevel)

	server := &http.Server{
		// G112 - Protect against Slowloris attack
		ReadHeaderTimeout: 5 * time.Second,

		Handler:  mux,
		ErrorLog: errorLog,
	}

	return &Server{server: server}
}

func (s *Server) Start(listener net.Listener) error {
	return s.server.Serve(listener)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// registerPprofHandlers registers the net/http/pprof endpoints on mux. pprof.Index also serves
// the named profiles such as /debug/pprof/heap and /debug/pprof/goroutine.
func registerPprofHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}

func registerCoreMetrics(reg *prometheus.Registry) {
	goCollector := collectors.NewGoCollector()

	processCollector := collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})

	reg.MustRegister(goCollector, processCollector)
}
