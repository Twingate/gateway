// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"gateway/internal/config"
	"gateway/internal/token"
)

type ProtocolListener struct {
	ch        <-chan Conn
	addr      net.Addr
	closed    chan struct{}
	closeOnce sync.Once
}

func NewProtocolListener(ch <-chan Conn, addr net.Addr) *ProtocolListener {
	return &ProtocolListener{
		ch:     ch,
		addr:   addr,
		closed: make(chan struct{}),
	}
}

func (l *ProtocolListener) Accept() (net.Conn, error) {
	// Check closed first to ensure that
	// Close() followed by Accept() will return ErrClosed
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}

	select {
	case conn, ok := <-l.ch:
		if !ok {
			return nil, net.ErrClosed
		}

		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *ProtocolListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
	})

	return nil
}

func (l *ProtocolListener) Addr() net.Addr {
	return l.addr
}

type ConnFactory func(net.Conn, *tls.Config, Validator, *zap.Logger) Conn

type Listener struct {
	channels map[token.ResourceType]chan<- Conn

	tokenParser      *token.Parser
	certReloader     *CertReloader
	tlsConfig        *tls.Config
	connectValidator Validator
	logger           *zap.Logger

	// Factory method for creating ProxyConn
	proxyConnFactory ConnFactory

	// Metrics
	metrics *ProxyConnMetrics
}

func NewListener(
	twingateConfig config.TwingateConfig,
	tlsCfg config.TLSConfig,
	channels map[token.ResourceType]chan<- Conn,
	registry *prometheus.Registry,
	logger *zap.Logger,
) (*Listener, error) {
	tokenParser, err := token.NewParser(token.ParserConfig{
		Issuer:   twingateConfig.Issuer(),
		Audience: twingateConfig.Network,
		JWKSURL:  twingateConfig.JWKSURL(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create token parser: %w", err)
	}

	certReloader := NewCertReloader(tlsCfg.CertificateFile, tlsCfg.PrivateKeyFile, logger)

	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		MaxVersion:     tls.VersionTLS13,
		GetCertificate: certReloader.GetCertificate,
	}

	connectValidator := &MessageValidator{
		TokenParser: tokenParser,
	}

	metrics := CreateProxyConnMetrics(registry)

	l := &Listener{
		channels:         channels,
		tokenParser:      tokenParser,
		certReloader:     certReloader,
		tlsConfig:        tlsConfig,
		connectValidator: connectValidator,
		logger:           logger,
		metrics:          metrics,
		proxyConnFactory: func(conn net.Conn, tlsConfig *tls.Config, connectValidator Validator, logger *zap.Logger) Conn {
			return NewProxyConn(conn, tlsConfig, connectValidator, logger, metrics)
		},
	}

	return l, nil
}

// Serve starts accepting connections and routing them to the appropriate channels.
// The caller owns the listener and is responsible for closing it.
// Serve closes the channels when it returns.
func (l *Listener) Serve(ctx context.Context, listener net.Listener) error {
	l.certReloader.Run(ctx)

	var wg sync.WaitGroup

	defer func() {
		wg.Wait()
		l.closeChannels()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				l.logger.Info("Listener closed")

				return nil
			}

			l.logger.Error("Failed to accept connection", zap.Error(err))

			return err
		}

		l.logger.Debug("Accepted connection", zap.String("remote addr", conn.RemoteAddr().String()))

		wg.Go(func() {
			proxyConn := l.proxyConnFactory(conn, l.tlsConfig, l.connectValidator, l.logger)

			if err := proxyConn.Authenticate(); err != nil {
				if !errors.Is(err, io.EOF) {
					l.logger.Error("Failed to authenticate connection", zap.Error(err))
				}

				_ = proxyConn.Close()

				return
			}

			resourceType := proxyConn.GATClaims().Resource.Type
			channel, exists := l.channels[resourceType]

			if !exists {
				l.logger.Error("Unsupported resource type", zap.String("resource_type", string(resourceType)))

				_ = proxyConn.Close()

				return
			}

			if proxyConn.GATClaims().ShouldUpgradeTLS() {
				if err := proxyConn.UpgradeToTLS(); err != nil {
					l.logger.Error("Failed to upgrade to TLS", zap.Error(err))

					_ = proxyConn.Close()

					return
				}
			}

			select {
			case channel <- proxyConn:
				// delivered successfully
			case <-ctx.Done():
				l.logger.Debug("Context canceled before routing connection to backend")

				_ = proxyConn.Close()
			}
		})
	}
}

func (l *Listener) closeChannels() {
	for _, ch := range l.channels {
		close(ch)
	}
}
