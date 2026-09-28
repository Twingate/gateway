// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapphandler

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"

	"go.uber.org/zap"

	"gateway/internal/config"
	"gateway/internal/metrics"
	"gateway/internal/webapphandler/template"
)

var errInvalidCACert = errors.New("failed to parse CA certificate")

type Config struct {
	requestHeaders      map[string]*template.Template
	caPool              *x509.CertPool
	roundTripperMetrics *metrics.RoundTripperMetrics
	logger              *zap.Logger
}

func NewConfig(configRequestHeaders map[string]string, caBundles []config.UpstreamCABundle, roundTripperMetrics *metrics.RoundTripperMetrics, logger *zap.Logger) (*Config, error) {
	headers := make(map[string]*template.Template, len(configRequestHeaders))

	for name, value := range configRequestHeaders {
		tmpl, err := template.New(value)
		if err != nil {
			return nil, fmt.Errorf("header %q: %w", name, err)
		}

		if key := tmpl.Key(); key != "" && !slices.Contains(template.AllowedWebAppKeys, key) {
			return nil, fmt.Errorf("header %q: %w %q", name, template.ErrUnsupportedKey, key)
		}

		headers[name] = tmpl
	}

	caPool, err := newCAPool(caBundles)
	if err != nil {
		return nil, err
	}

	return &Config{requestHeaders: headers, caPool: caPool, roundTripperMetrics: roundTripperMetrics, logger: logger}, nil
}

// newCAPool merges the configured CAs on top of the system cert pool to verify
// upstream TLS connections, so publicly-signed upstreams work without configuration.
func newCAPool(caBundles []config.UpstreamCABundle) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system cert pool: %w", err)
	}

	for _, caBundle := range caBundles {
		caCerts, err := os.ReadFile(caBundle.File) //nolint:gosec // The CA bundle file is provided by the operator
		if err != nil {
			return nil, fmt.Errorf("ca %q: %w", caBundle.File, err)
		}

		if ok := pool.AppendCertsFromPEM(caCerts); !ok {
			return nil, fmt.Errorf("ca %q: %w", caBundle.File, errInvalidCACert)
		}
	}

	return pool, nil
}
