// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapphandler

import (
	"errors"
	"fmt"
	"slices"

	"go.uber.org/zap"

	"gateway/internal/metrics"
	"gateway/internal/utils/parser"
)

var ErrUnsupportedVariable = errors.New("unsupported variable")

var allowedVariables = []string{
	"jwt", "username", "groups", "clientGeoLoc",
}

type Config struct {
	headers             map[string]*parser.Template
	roundTripperMetrics *metrics.RoundTripperMetrics
	logger              *zap.Logger
}

func NewConfig(rawHeaders map[string]string, roundTripperMetrics *metrics.RoundTripperMetrics, logger *zap.Logger) (*Config, error) {
	headers := make(map[string]*parser.Template, len(rawHeaders))

	for name, value := range rawHeaders {
		tmpl, err := parser.New(value)
		if err != nil {
			return nil, fmt.Errorf("header %q: %w", name, err)
		}

		variable := tmpl.Variable()
		if variable != "" && !slices.Contains(allowedVariables, variable) {
			return nil, fmt.Errorf("header %q: %w %q", name, ErrUnsupportedVariable, variable)
		}

		headers[name] = tmpl
	}

	return &Config{headers: headers, roundTripperMetrics: roundTripperMetrics, logger: logger}, nil
}
