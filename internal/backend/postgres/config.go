// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"crypto/x509"

	backendtls "gateway/internal/backend/tls"
	"gateway/internal/config"
	"gateway/internal/logging"
	"gateway/internal/metrics"
)

type Config struct {
	passwords passwordCredentials
	caPool    *x509.CertPool
	metrics   *metrics.DBResourceMetrics
	logger    logging.Logger
}

func NewConfig(
	pgCfg *config.PostgreSQLConfig,
	caBundles []config.UpstreamTrustedCABundle,
	dbMetrics *metrics.DBMetrics,
	logger logging.Logger,
) (*Config, error) {
	caPool, err := backendtls.NewCAPool(caBundles)
	if err != nil {
		return nil, err
	}

	return &Config{
		passwords: newPasswordCredentials(pgCfg.Credentials),
		caPool:    caPool,
		metrics:   dbMetrics.WithResourceType(metrics.ResourceTypePostgreSQL),
		logger:    logger,
	}, nil
}
