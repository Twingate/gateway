// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package kubernetes

import (
	"k8s.io/client-go/rest"

	"gateway/internal/config"
	"gateway/internal/metrics"
)

type Config struct {
	sessionRecording    *config.SessionRecordingConfig
	roundTripperMetrics *metrics.RoundTripperMetrics

	bearerToken     string
	bearerTokenFile string
	caFile          string
}

func NewConfig(sessionRecordingConfig *config.SessionRecordingConfig, k8sConfig *config.KubernetesConfig, roundTripperMetrics *metrics.RoundTripperMetrics) (*Config, error) {
	cfg := &Config{
		sessionRecording:    sessionRecordingConfig,
		roundTripperMetrics: roundTripperMetrics,
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
