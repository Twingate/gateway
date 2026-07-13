// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/connect"
	"gateway/internal/httpproxy"
	"gateway/internal/kuberneteshandler"
	"gateway/internal/metrics"
	"gateway/internal/sshhandler"
	"gateway/internal/token"
)

var fullConfig = gatewayconfig.Config{
	Twingate: gatewayconfig.TwingateConfig{
		Network: "acme",
		Host:    "test",
	},
	Port:        0,
	MetricsPort: 0,
	TLS: gatewayconfig.TLSConfig{
		CertificateFile: "../../test/data/proxy/tls.crt",
		PrivateKeyFile:  "../../test/data/proxy/tls.key",
	},
	Kubernetes: &gatewayconfig.KubernetesConfig{
		Upstreams: []gatewayconfig.KubernetesUpstream{
			{
				Name:        "k8s-cluster",
				BearerToken: "token",
				CAFile:      "../../test/data/api_server/tls.crt",
			},
		},
	},
	SSH: &gatewayconfig.SSHConfig{
		Gateway: gatewayconfig.SSHGatewayConfig{
			Username:        "gateway",
			Key:             gatewayconfig.SSHKeyConfig{},
			HostCertificate: gatewayconfig.SSHCertificateConfig{},
			UserCertificate: gatewayconfig.SSHCertificateConfig{},
		},
		CA: gatewayconfig.SSHCAConfig{},
	},
}

func TestNewProxy_Success(t *testing.T) {
	registry := prometheus.NewRegistry()
	logger, err := NewLogger(DefaultLoggerName, false)
	require.NoError(t, err)

	p, err := NewProxy(&fullConfig, registry, logger)

	require.NoError(t, err)
	assert.NotNil(t, p)
	assert.Equal(t, &fullConfig, p.config)
	assert.Equal(t, registry, p.registry)
	assert.Equal(t, logger, p.logger)

	assert.Len(t, p.httpProxies, 1)
	assert.Contains(t, p.httpProxies, token.ResourceTypeKubernetes)
	assert.NotNil(t, p.sshProxy)
	assert.NotNil(t, p.metricsServer)
}

func TestNewProxy_HTTPOnly(t *testing.T) {
	config := fullConfig
	config.SSH = nil
	config.WebApp = &gatewayconfig.WebAppConfig{RequestHeaders: map[string]string{}}

	registry := prometheus.NewRegistry()
	logger, err := NewLogger(DefaultLoggerName, false)
	require.NoError(t, err)

	p, err := NewProxy(&config, registry, logger)

	require.NoError(t, err)
	assert.NotNil(t, p)
	assert.Len(t, p.httpProxies, 2)
	assert.Contains(t, p.httpProxies, token.ResourceTypeKubernetes)
	assert.Contains(t, p.httpProxies, token.ResourceTypeWebApp)
	assert.Nil(t, p.sshProxy)
}

func TestNewProxy_SSHOnly(t *testing.T) {
	config := fullConfig
	config.Kubernetes = nil

	registry := prometheus.NewRegistry()
	logger, err := NewLogger(DefaultLoggerName, false)
	require.NoError(t, err)

	p, err := NewProxy(&config, registry, logger)

	require.NoError(t, err)
	assert.NotNil(t, p)
	assert.NotNil(t, p.sshProxy)
	assert.Empty(t, p.httpProxies)
}

func createTestProxy(t *testing.T) (*Proxy, net.Listener) {
	t.Helper()

	// Create a real TCP listener on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	metricsListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	registry := prometheus.NewRegistry()
	metricsServer := metrics.NewServer(metrics.Config{
		Registry: registry,
	})

	return &Proxy{
		logger:        zap.NewNop(),
		listener:      listener,
		metricsServer: metricsServer,
	}, metricsListener
}

func TestShutdown_ClosesAllComponents(t *testing.T) {
	p, metricsListener := createTestProxy(t)

	// Create and attach a real HTTP proxy
	registry := prometheus.NewRegistry()

	k8sConfig, err := kuberneteshandler.NewConfig(&gatewayconfig.AuditLogConfig{}, fullConfig.Kubernetes, metrics.RegisterRoundTripperMetrics(registry), zap.NewNop())
	require.NoError(t, err)

	k8sHandler, err := kuberneteshandler.NewHandler(*k8sConfig)
	require.NoError(t, err)

	httpProxy := httpproxy.NewProxy(httpproxy.Config{
		Handler:      k8sHandler,
		Metrics:      metrics.RegisterHTTPMetrics(registry),
		ResourceType: metrics.ResourceTypeKubernetes,
		Logger:       zap.NewNop(),
	})

	p.httpProxies = map[token.ResourceType]*httpproxy.Proxy{
		token.ResourceTypeKubernetes: httpProxy,
	}

	// Start HTTP proxy on a protocol listener
	httpChannel := make(chan connect.Conn)
	httpListener := connect.NewProtocolListener(httpChannel, p.listener.Addr())

	httpDone := make(chan error, 1)

	go func() {
		httpDone <- httpProxy.Start(httpListener)
	}()

	// Create and attach a real SSH proxy
	sshConfig, err := sshhandler.NewConfig(
		&gatewayconfig.AuditLogConfig{},
		fullConfig.SSH,
		zap.NewNop(),
	)
	require.NoError(t, err)

	p.sshProxy = sshhandler.NewProxy(*sshConfig)

	// Start metrics server
	go func() {
		_ = p.metricsServer.Start(metricsListener)
	}()

	listenerAddr := p.listener.Addr().String()
	metricsAddr := fmt.Sprintf("http://%s/metrics", metricsListener.Addr().String())

	p.shutdown()

	// Listener should be closed
	_, err = net.DialTimeout("tcp", listenerAddr, 100*time.Millisecond)
	require.Error(t, err)

	// Metrics server should be closed
	client := &http.Client{Timeout: 100 * time.Millisecond}

	resp, err := client.Get(metricsAddr) //nolint:noctx
	if resp != nil {
		_ = resp.Body.Close()
	}

	require.Error(t, err)

	// HTTP proxy should have stopped with ErrServerClosed
	close(httpChannel)

	select {
	case httpErr := <-httpDone:
		require.ErrorIs(t, httpErr, http.ErrServerClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for HTTP proxy to stop")
	}
}

func TestShutdown_IsIdempotent(t *testing.T) {
	p, metricsListener := createTestProxy(t)

	go func() {
		_ = p.metricsServer.Start(metricsListener)
	}()

	// Calling shutdown multiple times should not panic
	p.shutdown()
	p.shutdown()
}

func TestShutdown_NilComponents(t *testing.T) {
	registry := prometheus.NewRegistry()
	metricsServer := metrics.NewServer(metrics.Config{
		Registry: registry,
	})

	metricsListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		_ = metricsServer.Start(metricsListener)
	}()

	p := &Proxy{
		logger:        zap.NewNop(),
		listener:      nil,
		httpProxies:   nil,
		sshProxy:      nil,
		metricsServer: metricsServer,
	}

	// Should not panic with nil listener, httpProxies, and sshProxy
	p.shutdown()
}
