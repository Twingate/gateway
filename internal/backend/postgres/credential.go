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

var (
	errUnsupportedAuthType   = errors.New("unsupported auth type")
	errUnknownCredential     = errors.New("unknown credential")
	errFailedToGetCredential = errors.New("failed to get the database credential")
)

type credential struct {
	user     string
	password string
	// certificate is served when the database asks for a client certificate during the TLS handshake.
	certificate *tls.Certificate
	// requireAuth is the only authentication method the Gateway authenticates with, and the
	// connection fails if the database asks for any other: scram-sha-256 for a password,
	// cleartext password for an IAM token.
	requireAuth string
}

type credentialProvider interface {
	retrieve(ctx context.Context) (credential, error)
}

// newCredentialProvider builds the provider for the auth entry's type, holding what it needs to
// produce the database credential.
func newCredentialProvider(auth token.Auth, passwords passwordCredentials) (credentialProvider, error) {
	switch auth.Type {
	case token.AuthTypePassword:
		return newPasswordCredential(passwords, auth.User, auth.Password)
	case token.AuthTypeAWSIAM:
		return newAWSIAMCredential(auth.User), nil
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
	user string
	cfg  config.PostgreSQLCredential
}

func newPasswordCredential(
	passwords passwordCredentials, user string, auth *token.PasswordAuth,
) (*passwordCredential, error) {
	cfg, ok := passwords[auth.Credential]
	if !ok {
		return nil, fmt.Errorf("%w: %q", errUnknownCredential, auth.Credential)
	}

	return &passwordCredential{user: user, cfg: cfg}, nil
}

func (c *passwordCredential) retrieve(_ context.Context) (credential, error) {
	cred, err := loadCredential(c.cfg)
	if err != nil {
		return credential{}, fmt.Errorf("credential %q: %w", c.cfg.Name, err)
	}

	cred.user = c.user
	cred.requireAuth = "scram-sha-256"

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

type awsIAMCredential struct {
	user string
}

func newAWSIAMCredential(user string) *awsIAMCredential {
	return &awsIAMCredential{user: user}
}

func (c *awsIAMCredential) retrieve(_ context.Context) (credential, error) {
	return credential{user: c.user, password: awsIAMPlaceholder, requireAuth: "password"}, nil
}
