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

	"gateway/internal/backend/httpproxy"
	"gateway/internal/backend/kubernetes"
	"gateway/internal/backend/postgres"
	"gateway/internal/backend/ssh"
	"gateway/internal/backend/webapp"
	gatewayconfig "gateway/internal/config"
	"gateway/internal/frontend"
	"gateway/internal/logging"
	"gateway/internal/metrics"
	"gateway/internal/sessionrecorder"
	"gateway/internal/token"
)

const shutdownTimeout = 30 * time.Second

type Proxy struct {
	config   *gatewayconfig.Config
	registry *prometheus.Registry
	logger   logging.Logger

	httpProxies   map[token.ResourceType]*httpproxy.Proxy
	sshProxy      *ssh.Proxy
	pgProxy       *postgres.Proxy
	metricsServer *metrics.Server

	listener     net.Listener
	shutdownOnce sync.Once
}

func NewProxy(config *gatewayconfig.Config, registry *prometheus.Registry, logger logging.Logger) (*Proxy, error) {
	httpProxies := make(map[token.ResourceType]*httpproxy.Proxy)

	var (
		roundTripperMetrics *metrics.RoundTripperMetrics
		httpMetrics         *metrics.HTTPMetrics
	)

	if config.Kubernetes != nil || config.WebApp != nil {
		roundTripperMetrics = metrics.RegisterRoundTripperMetrics(registry)
		httpMetrics = metrics.RegisterHTTPMetrics(registry)
	}

	if config.Kubernetes != nil {
		k8sConfig, err := kubernetes.NewConfig(&config.Log.SessionRecording, config.Kubernetes, roundTripperMetrics, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create Kubernetes config: %w", err)
		}

		k8sHandler, err := kubernetes.NewHandler(*k8sConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create Kubernetes handler: %w", err)
		}

		httpProxies[token.ResourceTypeKubernetes] = httpproxy.NewProxy(httpproxy.Config{
			Handler:      k8sHandler,
			Metrics:      httpMetrics,
			Logger:       logger,
			ResourceType: metrics.ResourceTypeKubernetes,
		})
	}

	if config.WebApp != nil {
		webAppCfg, err := webapp.NewConfig(config.WebApp.RequestHeaders, config.UpstreamTrustedCABundles, roundTripperMetrics, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create web app config: %w", err)
		}

		webAppHandler := webapp.NewHandler(*webAppCfg)

		httpProxies[token.ResourceTypeWebApp] = httpproxy.NewProxy(httpproxy.Config{
			Handler:      webAppHandler,
			Metrics:      httpMetrics,
			Logger:       logger,
			ResourceType: metrics.ResourceTypeWebApp,
		})
	}

	var sshProxy *ssh.Proxy

	if config.SSH != nil {
		sshConfig, err := ssh.NewConfig(&config.Log.SessionRecording, config.SSH, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create SSH config: %w", err)
		}

		sshProxy = ssh.NewProxy(*sshConfig)
	}

	var pgProxy *postgres.Proxy

	if config.PostgreSQL != nil {
		pgConfig, err := postgres.NewConfig(config.PostgreSQL, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create PostgreSQL config: %w", err)
		}

		pgProxy = postgres.NewProxy(*pgConfig)
	}

	sessionrecorder.RegisterRecordedSessionMetrics(metrics.Namespace, registry)

	metricsServer := metrics.NewServer(metrics.Config{
		Registry: registry,
		Logger:   logger.System,
	})

	return &Proxy{
		config:   config,
		registry: registry,
		logger:   logger,

		httpProxies:   httpProxies,
		sshProxy:      sshProxy,
		pgProxy:       pgProxy,
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

	channels := make(map[token.ResourceType]chan<- frontend.Conn)

	var sshListener, pgListener *frontend.ProtocolListener

	if p.sshProxy != nil {
		sshListener = protocolListener(channels, token.ResourceTypeSSH, listener.Addr())
	}

	if p.pgProxy != nil {
		pgListener = protocolListener(channels, token.ResourceTypePostgres, listener.Addr())
	}

	httpListeners := make(map[token.ResourceType]*frontend.ProtocolListener)

	for resourceType := range p.httpProxies {
		httpListeners[resourceType] = protocolListener(channels, resourceType, listener.Addr())
	}

	connectListener, err := frontend.NewListener(
		ctx,
		p.config.Twingate,
		p.config.TLS,
		channels,
		p.registry,
		p.logger.System,
	)
	if err != nil {
		return fmt.Errorf("failed to create connect listener: %w", err)
	}

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		p.logger.System.Info("Starting connect proxy", zap.Int("port", p.config.Port))

		err := connectListener.Serve(gCtx, listener)
		if err != nil {
			p.logger.System.Error("Connect proxy stopped with error", zap.Error(err))
		}

		return err
	})

	if p.sshProxy != nil {
		p.goServe(gCtx, g, "SSH", sshListener, p.sshProxy.Start)
	}

	for resourceType, proxy := range p.httpProxies {
		g.Go(func() error {
			p.logger.System.Info("Starting HTTP proxy", zap.String("resource_type", string(resourceType)))

			err := proxy.Start(httpListeners[resourceType])
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}

			if err != nil {
				p.logger.System.Error("HTTP proxy stopped with error",
					zap.String("resource_type", string(resourceType)),
					zap.Error(err))
			}

			return err
		})
	}

	if p.pgProxy != nil {
		p.goServe(gCtx, g, "PostgreSQL", pgListener, p.pgProxy.Start)
	}

	metricsListener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.config.MetricsPort))
	if err != nil {
		return fmt.Errorf("failed to create metrics listener: %w", err)
	}

	g.Go(func() error {
		p.logger.System.Info("Starting metrics server", zap.String("addr", metricsListener.Addr().String()))

		err := p.metricsServer.Start(metricsListener)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		if err != nil {
			p.logger.System.Error("Metrics server stopped with error", zap.Error(err))
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
		p.logger.System.Error("Proxy component error", zap.Error(err))
	}

	return err
}

// protocolListener registers a channel for resourceType so the connect listener
// can dispatch matching connections into it, and wraps it in a net.Listener the
// handler for that protocol accepts from.
func protocolListener(
	channels map[token.ResourceType]chan<- frontend.Conn,
	resourceType token.ResourceType,
	addr net.Addr,
) *frontend.ProtocolListener {
	ch := make(chan frontend.Conn)
	channels[resourceType] = ch

	return frontend.NewProtocolListener(ch, addr)
}

// goServe runs a protocol handler's accept loop in g, logging where it stopped.
func (p *Proxy) goServe(
	ctx context.Context,
	g *errgroup.Group,
	name string,
	listener net.Listener,
	start func(context.Context, net.Listener) error,
) {
	g.Go(func() error {
		p.logger.System.Info("Starting " + name + " proxy")

		err := start(ctx, listener)
		if err != nil {
			p.logger.System.Error(name+" proxy stopped with error", zap.Error(err))
		}

		return err
	})
}

func (p *Proxy) shutdown() {
	p.shutdownOnce.Do(func() {
		p.logger.System.Info("Starting graceful shutdown")

		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if p.listener != nil {
			if err := p.listener.Close(); err != nil {
				p.logger.System.Error("Failed to close TCP listener", zap.Error(err))
			}
		}

		for resourceType, proxy := range p.httpProxies {
			if err := proxy.Shutdown(ctx); err != nil {
				p.logger.System.Error("Failed to shut down HTTP proxy",
					zap.String("resource_type", string(resourceType)),
					zap.Error(err))
			}
		}

		if p.sshProxy != nil {
			p.sshProxy.Shutdown(ctx)
		}

		if p.pgProxy != nil {
			p.pgProxy.Shutdown(ctx)
		}

		if err := p.metricsServer.Shutdown(ctx); err != nil {
			p.logger.System.Error("Failed to shut down metrics server", zap.Error(err))
		}

		p.logger.System.Info("Graceful shutdown complete")
	})
}
