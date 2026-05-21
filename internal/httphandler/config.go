// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httphandler

import (
	"go.uber.org/zap"
	"k8s.io/client-go/rest"

	"gateway/internal/config"
	"gateway/internal/metrics"
)

type Config struct {
	auditLog               *config.AuditLogConfig
	roundTripperCollectors *metrics.RoundTripperCollectors

	bearerToken     string
	bearerTokenFile string
	caFile          string
	logger          *zap.Logger
}

func NewConfig(auditLogConfig *config.AuditLogConfig, k8sConfig *config.KubernetesConfig, collectors *metrics.RoundTripperCollectors, logger *zap.Logger) (*Config, error) {
	cfg := &Config{
		auditLog:               auditLogConfig,
		roundTripperCollectors: collectors,
		logger:                 logger,
	}

	if len(k8sConfig.Upstreams) == 0 {
		if err := cfg.loadInClusterCredentials(); err != nil {
			return nil, err
		}

		return cfg, nil
	}

	upstream := k8sConfig.Upstreams[0]
	cfg.bearerToken = upstream.BearerToken
	cfg.bearerTokenFile = upstream.BearerTokenFile
	cfg.caFile = upstream.CAFile

	return cfg, nil
}

func (c *Config) loadInClusterCredentials() error {
	inCluster, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	c.bearerToken = inCluster.BearerToken
	c.bearerTokenFile = inCluster.BearerTokenFile
	c.caFile = inCluster.CAFile

	return nil
}
