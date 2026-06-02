// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapphandler

import (
	"fmt"

	"go.uber.org/zap"

	"gateway/internal/httpproxy/parser"
	"gateway/internal/metrics"
)

type Config struct {
	headers             map[string]*parser.Template
	roundTripperMetrics *metrics.RoundTripperMetrics
	logger              *zap.Logger
}

func NewConfig(configHeaders map[string]string, roundTripperMetrics *metrics.RoundTripperMetrics, logger *zap.Logger) (*Config, error) {
	headers := make(map[string]*parser.Template, len(configHeaders))

	for name, value := range configHeaders {
		tmpl, err := parser.NewTemplate(value)
		if err != nil {
			return nil, fmt.Errorf("header %q: %w", name, err)
		}

		headers[name] = tmpl
	}

	return &Config{headers: headers, roundTripperMetrics: roundTripperMetrics, logger: logger}, nil
}
