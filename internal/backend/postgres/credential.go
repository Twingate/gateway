// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"

	"gateway/internal/config"
	"gateway/internal/token"
)

var errUnknownCredential = errors.New("unknown credential")

type credential struct {
	password string
	// certificate is served when the database asks for a client certificate during the TLS handshake.
	certificate *tls.Certificate
}

type passwordCredentials map[string]config.PostgreSQLCredential

func newPasswordCredentials(credentials []config.PostgreSQLCredential) passwordCredentials {
	byName := make(passwordCredentials, len(credentials))

	for _, cfg := range credentials {
		byName[cfg.Name] = cfg
	}

	return byName
}

func (c passwordCredentials) credential(_ context.Context, auth token.Auth) (credential, error) {
	cfg, ok := c[auth.Password.Credential]
	if !ok {
		return credential{}, fmt.Errorf("%w: %q", errUnknownCredential, auth.Password.Credential)
	}

	cred, err := loadCredential(cfg)
	if err != nil {
		return credential{}, fmt.Errorf("credential %q: %w", cfg.Name, err)
	}

	return cred, nil
}

func loadCredential(cfg config.PostgreSQLCredential) (credential, error) {
	cred := credential{password: cfg.Password}

	if cfg.PasswordFile != "" {
		content, err := os.ReadFile(cfg.PasswordFile)
		if err != nil {
			return credential{}, fmt.Errorf("failed to read password file: %w", err)
		}

		cred.password = strings.TrimRight(string(content), "\r\n")
	}

	if cfg.ClientCertificateFile != "" && cfg.ClientPrivateKeyFile != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.ClientCertificateFile, cfg.ClientPrivateKeyFile)
		if err != nil {
			return credential{}, fmt.Errorf("failed to load client certificate: %w", err)
		}

		cred.certificate = &certificate
	}

	return cred, nil
}
