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

// awsIAMPlaceholder is the password the aws_iam provider returns until it signs an RDS auth token.
const awsIAMPlaceholder = "aws-iam-token"

var errUnknownCredential = errors.New("unknown credential")

type credential struct {
	password string
	// certificate is served when the database asks for a client certificate during the TLS handshake.
	certificate *tls.Certificate
}

type credentialProvider interface {
	credential(ctx context.Context) (credential, error)
}

// newCredentialProvider builds the provider for the auth entry's type, holding what it needs to
// produce the database credential.
func newCredentialProvider(auth token.Auth, passwords passwordCredentials) (credentialProvider, error) {
	switch auth.Type {
	case token.AuthTypePassword:
		return newPasswordCredential(passwords, auth.Password)
	case token.AuthTypeAWSIAM:
		return newAWSIAMCredential()
	case token.AuthTypeGCPIAM:
		fallthrough
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedAuthType, auth.Type)
	}
}

type passwordCredentials map[string]config.PostgreSQLCredential

func newPasswordCredentials(credentials []config.PostgreSQLCredential) passwordCredentials {
	byName := make(passwordCredentials, len(credentials))

	for _, cfg := range credentials {
		byName[cfg.Name] = cfg
	}

	return byName
}

// passwordCredential is the credential provider for the password auth type: a credential
// configured on the Gateway.
type passwordCredential struct {
	cfg config.PostgreSQLCredential
}

func newPasswordCredential(passwords passwordCredentials, auth *token.PasswordAuth) (*passwordCredential, error) {
	cfg, ok := passwords[auth.Credential]
	if !ok {
		return nil, fmt.Errorf("%w: %q", errUnknownCredential, auth.Credential)
	}

	return &passwordCredential{cfg: cfg}, nil
}

func (c *passwordCredential) credential(_ context.Context) (credential, error) {
	cred, err := loadCredential(c.cfg)
	if err != nil {
		return credential{}, fmt.Errorf("credential %q: %w", c.cfg.Name, err)
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

type awsIAMCredential struct{}

func newAWSIAMCredential() (*awsIAMCredential, error) {
	return &awsIAMCredential{}, nil
}

func (c *awsIAMCredential) credential(_ context.Context) (credential, error) {
	return credential{password: awsIAMPlaceholder}, nil
}
