// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"context"
	"net"
	"net/http"
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

func registerCoreMetrics(reg *prometheus.Registry) {
	goCollector := collectors.NewGoCollector()

	processCollector := collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})

	reg.MustRegister(goCollector, processCollector)
}
