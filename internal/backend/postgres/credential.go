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

	"cloud.google.com/go/auth/credentials/impersonate"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	googleauth "cloud.google.com/go/auth"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	rdsauth "github.com/aws/aws-sdk-go-v2/feature/rds/auth"

	"gateway/internal/config"
	"gateway/internal/token"
)

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
	get(ctx context.Context) (credential, error)
}

// newCredentialProvider builds the provider for the auth entry's type, holding what it needs to
// produce the database credential.
func newCredentialProvider(upstreamAddress string, auth token.Auth, passwords passwordCredentials) (credentialProvider, error) {
	switch auth.Type {
	case token.AuthTypePassword:
		return newPasswordCredential(passwords, auth.User, auth.Password)
	case token.AuthTypeAWSIAM:
		return newAWSIAMCredential(upstreamAddress, auth.User, auth.AWSIAM), nil
	case token.AuthTypeGCPIAM:
		return newGCPIAMCredential(auth.User, auth.GCPIAM), nil
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

func (c *passwordCredential) get(_ context.Context) (credential, error) {
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

var (
	errFailedToLoadAWSConfig = errors.New("failed to load AWS config")
	errFailedToBuildRDSToken = errors.New("failed to build AWS RDS auth token")
)

// awsIAMCredential is the credential provider for the aws_iam auth type: an RDS auth token, which
// the database takes as the password.
type awsIAMCredential struct {
	upstreamAddress string
	user            string
	auth            *token.AWSIAMAuth
}

func newAWSIAMCredential(upstreamAddress string, user string, auth *token.AWSIAMAuth) *awsIAMCredential {
	return &awsIAMCredential{upstreamAddress: upstreamAddress, user: user, auth: auth}
}

func (c *awsIAMCredential) get(ctx context.Context) (credential, error) {
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(c.auth.Region))
	if err != nil {
		return credential{}, fmt.Errorf("%w: %w", errFailedToLoadAWSConfig, err)
	}

	creds := awsConfig.Credentials
	if c.auth.AssumeRoleARN != "" {
		creds = stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsConfig), c.auth.AssumeRoleARN)
	}

	authToken, err := rdsauth.BuildAuthToken(ctx, c.upstreamAddress, c.auth.Region, c.user, creds)
	if err != nil {
		return credential{}, fmt.Errorf("%w: %w", errFailedToBuildRDSToken, err)
	}

	return credential{user: c.user, password: authToken, requireAuth: "password"}, nil
}

const (
	// cloudSQLLoginScope limits the access token to logging in to Cloud SQL.
	cloudSQLLoginScope = "https://www.googleapis.com/auth/sqlservice.login"
	// serviceAccountSuffix the GCP service account's email suffix.
	serviceAccountSuffix = ".gserviceaccount.com"
)

var (
	errFailedToLoadGCPCredentials = errors.New("failed to load GCP credentials")
	errFailedToFetchGCPToken      = errors.New("failed to fetch GCP access token")
)

// gcpIAMCredential is the credential provider for the gcp_iam auth type: a service account's
// access token, which Cloud SQL takes as the password.
type gcpIAMCredential struct {
	user             string
	serviceAccount   string
	newTokenProvider func(serviceAccount string) (googleauth.TokenProvider, error)
}

func newGCPIAMCredential(user string, auth *token.GCPIAMAuth) *gcpIAMCredential {
	serviceAccount := auth.ImpersonateServiceAccount
	if serviceAccount == "" {
		serviceAccount = user + serviceAccountSuffix
	}

	return &gcpIAMCredential{user: user, serviceAccount: serviceAccount, newTokenProvider: newGCPTokenProvider}
}

func newGCPTokenProvider(serviceAccount string) (googleauth.TokenProvider, error) {
	return impersonate.NewCredentials(&impersonate.CredentialsOptions{
		TargetPrincipal: serviceAccount,
		Scopes:          []string{cloudSQLLoginScope},
	})
}

func (c *gcpIAMCredential) get(ctx context.Context) (credential, error) {
	provider, err := c.newTokenProvider(c.serviceAccount)
	if err != nil {
		return credential{}, fmt.Errorf("%w: %w", errFailedToLoadGCPCredentials, err)
	}

	gcpToken, err := provider.Token(ctx)
	if err != nil {
		return credential{}, fmt.Errorf("%w: %w", errFailedToFetchGCPToken, err)
	}

	return credential{user: c.user, password: gcpToken.Value, requireAuth: "password"}, nil
}
