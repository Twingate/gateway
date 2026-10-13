// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"fmt"
	"os"
	"strings"

	"gateway/internal/config"
	"gateway/internal/logging"
)

type Config struct {
	passwordsByCredential map[string]string

	logger logging.Logger
}

// NewConfig creates a PostgreSQL handler config from the config package types.
// Passwords supplied via PasswordFile are read from disk at startup so failures
// surface immediately rather than on the first connection.
func NewConfig(pgCfg *config.PostgreSQLConfig, logger logging.Logger) (*Config, error) {
	passwords := make(map[string]string, len(pgCfg.Credentials))

	for _, c := range pgCfg.Credentials {
		password, err := resolvePassword(c)
		if err != nil {
			return nil, fmt.Errorf("credential %q: %w", c.Name, err)
		}

		passwords[c.Name] = password
	}

	return &Config{
		passwordsByCredential: passwords,
		logger:                logger,
	}, nil
}

func resolvePassword(c config.PostgreSQLCredential) (string, error) {
	if c.Password != "" {
		return c.Password, nil
	}

	// #nosec G304 -- file path is from trusted operator configuration
	data, err := os.ReadFile(c.PasswordFile)
	if err != nil {
		return "", fmt.Errorf("failed to read passwordFile %q: %w", c.PasswordFile, err)
	}

	// Allow passwords written as "secret\n" by operators using `echo secret > file`.
	return strings.TrimRight(string(data), "\r\n"), nil
}
