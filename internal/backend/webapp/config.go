// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapp

import (
	"crypto/x509"
	"fmt"
	"slices"

	backendtls "gateway/internal/backend/tls"
	"gateway/internal/backend/webapp/template"
	"gateway/internal/config"
	"gateway/internal/logging"
	"gateway/internal/metrics"
)

type Config struct {
	requestHeaders      map[string]*template.Template
	caPool              *x509.CertPool
	roundTripperMetrics *metrics.RoundTripperMetrics
	logger              logging.Logger
}

func NewConfig(configRequestHeaders map[string]string, caBundles []config.UpstreamTrustedCABundle, roundTripperMetrics *metrics.RoundTripperMetrics, logger logging.Logger) (*Config, error) {
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

	caPool, err := backendtls.NewCAPool(caBundles)
	if err != nil {
		return nil, err
	}

	return &Config{requestHeaders: headers, caPool: caPool, roundTripperMetrics: roundTripperMetrics, logger: logger}, nil
}
