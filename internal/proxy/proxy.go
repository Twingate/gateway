// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/connect"
	"gateway/internal/httpproxy"
	"gateway/internal/kuberneteshandler"
	"gateway/internal/metrics"
	"gateway/internal/sessionrecorder"
	"gateway/internal/sshhandler"
	"gateway/internal/token"
	"gateway/internal/webapphandler"
)

const shutdownTimeout = 30 * time.Second

type Proxy struct {
	config   *gatewayconfig.Config
	registry *prometheus.Registry
	logger   *zap.Logger

	httpProxy     *httpproxy.Proxy
	sshProxy      *sshhandler.SSHProxy
	metricsServer *metrics.Server

	listener     net.Listener
	shutdownOnce sync.Once
}

func NewProxy(config *gatewayconfig.Config, registry *prometheus.Registry, logger *zap.Logger) (*Proxy, error) {
	var httpProxy *httpproxy.Proxy

	handlers := make(map[string]http.Handler)

	roundTripperMetrics := metrics.RegisterRoundTripperMetrics(registry)

	if config.Kubernetes != nil {
		k8sConfig, err := kuberneteshandler.NewConfig(&config.AuditLog, config.Kubernetes, roundTripperMetrics, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create Kubernetes config: %w", err)
		}

		k8sHandler, err := kuberneteshandler.NewHandler(*k8sConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create Kubernetes handler: %w", err)
		}

		handlers[token.ResourceTypeKubernetes] = k8sHandler
	}

	if config.WebApp != nil {
		webAppCfg, err := webapphandler.NewConfig(config.WebApp.Headers, roundTripperMetrics, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create web app config: %w", err)
		}

		webAppHandler := webapphandler.NewHandler(*webAppCfg)
		handlers[token.ResourceTypeWebApp] = webAppHandler
	}

	if len(handlers) > 0 {
		httpProxy = httpproxy.NewProxy(httpproxy.Config{
			Handlers: handlers,
			Registry: registry,
			Logger:   logger,
		})
	}

	var sshProxy *sshhandler.SSHProxy

	if config.SSH != nil {
		sshConfig, err := sshhandler.NewConfig(&config.AuditLog, config.SSH, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create SSH config: %w", err)
		}

		sshProxy = sshhandler.NewProxy(*sshConfig)
	}

	sessionrecorder.RegisterRecordedSessionMetrics(metrics.Namespace, registry)

	metricsServer := metrics.NewServer(metrics.Config{
		Registry: registry,
	})

	return &Proxy{
		config:   config,
		registry: registry,
		logger:   logger,

		httpProxy:     httpProxy,
		sshProxy:      sshProxy,
		metricsServer: metricsServer,
	}, nil
}

func (p *Proxy) Start() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.config.Port))
	if err != nil {
		return err
	}

	p.listener = listener

	channels := make(map[connect.TransportProtocol]chan<- connect.Conn)

	var sshListener *connect.ProtocolListener

	if p.sshProxy != nil {
		sshChannel := make(chan connect.Conn)
		channels[connect.TransportSSH] = sshChannel
		sshListener = connect.NewProtocolListener(sshChannel, listener.Addr())
	}

	var httpListener *connect.ProtocolListener

	if p.httpProxy != nil {
		httpChannel := make(chan connect.Conn)
		channels[connect.TransportTLS] = httpChannel
		httpListener = connect.NewProtocolListener(httpChannel, listener.Addr())
	}

	connectListener, err := connect.NewListener(
		p.config.Twingate,
		p.config.TLS,
		channels,
		p.registry,
		p.logger,
	)
	if err != nil {
		return fmt.Errorf("failed to create connect listener: %w", err)
	}

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		p.logger.Info("Starting connect proxy", zap.Int("port", p.config.Port))

		err := connectListener.Serve(gCtx, listener)
		if err != nil {
			p.logger.Error("Connect proxy stopped with error", zap.Error(err))
		}

		return err
	})

	if p.sshProxy != nil {
		g.Go(func() error {
			p.logger.Info("Starting SSH proxy")

			err := p.sshProxy.Start(gCtx, sshListener)
			if err != nil {
				p.logger.Error("SSH proxy stopped with error", zap.Error(err))
			}

			return err
		})
	}

	if p.httpProxy != nil {
		g.Go(func() error {
			p.logger.Info("Starting HTTP proxy")

			err := p.httpProxy.Start(httpListener)
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}

			if err != nil {
				p.logger.Error("HTTP proxy stopped with error", zap.Error(err))
			}

			return err
		})
	}

	metricsListener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.config.MetricsPort))
	if err != nil {
		return fmt.Errorf("failed to create metrics listener: %w", err)
	}

	g.Go(func() error {
		p.logger.Info("Starting metrics server", zap.String("addr", metricsListener.Addr().String()))

		err := p.metricsServer.Start(metricsListener)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		if err != nil {
			p.logger.Error("Metrics server stopped with error", zap.Error(err))
		}

		return err
	})

	g.Go(func() error {
		<-gCtx.Done()
		p.shutdown() //nolint:contextcheck

		return nil
	})

	err = g.Wait()
	if err != nil {
		p.logger.Error("Proxy component error", zap.Error(err))
	}

	return err
}

func (p *Proxy) shutdown() {
	p.shutdownOnce.Do(func() {
		p.logger.Info("Starting graceful shutdown")

		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if p.listener != nil {
			if err := p.listener.Close(); err != nil {
				p.logger.Error("Failed to close TCP listener", zap.Error(err))
			}
		}

		if p.httpProxy != nil {
			if err := p.httpProxy.Shutdown(ctx); err != nil {
				p.logger.Error("Failed to shut down HTTP proxy", zap.Error(err))
			}
		}

		if p.sshProxy != nil {
			p.sshProxy.Shutdown(ctx)
		}

		if err := p.metricsServer.Shutdown(ctx); err != nil {
			p.logger.Error("Failed to shut down metrics server", zap.Error(err))
		}

		p.logger.Info("Graceful shutdown complete")
	})
}
