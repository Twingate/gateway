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

func NewConfig(configRequestHeaders map[string]string, cas []config.CA, roundTripperMetrics *metrics.RoundTripperMetrics, logger *zap.Logger) (*Config, error) {
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

	caPool, err := newCAPool(cas)
	if err != nil {
		return nil, err
	}

	return &Config{requestHeaders: headers, caPool: caPool, roundTripperMetrics: roundTripperMetrics, logger: logger}, nil
}

// newCAPool merges the configured CAs into the pool used to verify upstream TLS connections.
// The pool never includes system roots, so an empty list rejects every upstream certificate.
func newCAPool(cas []config.CA) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	for _, ca := range cas {
		caCert, err := os.ReadFile(ca.CertFile) //nolint:gosec // The CA file is provided by the operator
		if err != nil {
			return nil, fmt.Errorf("ca %q: %w", ca.Name, err)
		}

		if ok := pool.AppendCertsFromPEM(caCert); !ok {
			return nil, fmt.Errorf("ca %q: %w", ca.Name, errInvalidCACert)
		}
	}

	return pool, nil
}
