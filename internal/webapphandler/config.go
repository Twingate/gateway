// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapphandler

import (
	"fmt"
	"slices"

	"go.uber.org/zap"

	"gateway/internal/metrics"
	"gateway/internal/webapphandler/template"
)

type Config struct {
	requestHeaders      map[string]*template.Template
	roundTripperMetrics *metrics.RoundTripperMetrics
	logger              *zap.Logger
}

func NewConfig(configRequestHeaders map[string]string, roundTripperMetrics *metrics.RoundTripperMetrics, logger *zap.Logger) (*Config, error) {
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

	return &Config{requestHeaders: headers, roundTripperMetrics: roundTripperMetrics, logger: logger}, nil
}
