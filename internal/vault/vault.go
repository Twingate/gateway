// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

// Package vault manages Vault API clients shared by the Vault-backed CAs.
package vault

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/hashicorp/vault/api/auth/aws"
	"github.com/hashicorp/vault/api/auth/gcp"
	"go.uber.org/zap"

	vaultapi "github.com/hashicorp/vault/api"

	"gateway/internal/config"
)

var errVaultAuthMethodNotConfigured = errors.New("no Vault auth method configured")

const (
	loginRetryInterval = time.Minute
)

//nolint:ireturn
func newVaultAuthMethod(authConfig *config.VaultAuthConfig, logger *zap.Logger) (vaultapi.AuthMethod, error) {
	if authConfig.AppRole != nil {
		return newAppRoleAuthMethod(authConfig.AppRole)
	}

	if authConfig.GCP != nil {
		return newGCPAuthMethod(authConfig.GCP)
	}

	if authConfig.AWS != nil {
		return newAWSAuthMethod(authConfig.AWS, logger)
	}

	return nil, errVaultAuthMethodNotConfigured
}

func newAppRoleAuthMethod(appRoleConfig *config.VaultAppRoleConfig) (*approle.AppRoleAuth, error) {
	secretID := &approle.SecretID{
		FromString: appRoleConfig.SecretID,
		FromFile:   appRoleConfig.SecretIDFile,
	}

	return approle.NewAppRoleAuth(
		appRoleConfig.RoleID,
		secretID,
		approle.WithMountPath(appRoleConfig.GetMount()),
	)
}

func newGCPAuthMethod(gcpConfig *config.VaultGCPConfig) (*gcp.GCPAuth, error) {
	opts := []gcp.LoginOption{
		gcp.WithMountPath(gcpConfig.GetMount()),
	}

	// GCE is the default in the Vault GCP auth SDK
	if strings.EqualFold(gcpConfig.Type, "iam") {
		opts = append(opts, gcp.WithIAMAuth(gcpConfig.ServiceAccountEmail))
	}

	return gcp.NewGCPAuth(gcpConfig.Role, opts...)
}

func newAWSAuthMethod(awsConfig *config.VaultAWSConfig, logger *zap.Logger) (*aws.AWSAuth, error) {
	opts := []aws.LoginOption{
		aws.WithRole(awsConfig.Role),
		aws.WithMountPath(awsConfig.GetMount()),
	}

	if awsConfig.Region != "" {
		opts = append(opts, aws.WithRegion(awsConfig.Region))
	}

	if awsConfig.IAMServerIDHeader != "" {
		opts = append(opts, aws.WithIAMServerIDHeader(awsConfig.IAMServerIDHeader))
	}

	if strings.EqualFold(awsConfig.Type, "iam") {
		opts = append(opts, aws.WithIAMAuth())

		return aws.NewAWSAuth(opts...)
	}

	opts = append(opts, aws.WithEC2Auth())

	if awsConfig.Nonce != "" {
		opts = append(opts, aws.WithNonce(awsConfig.Nonce))
	}

	switch strings.ToLower(awsConfig.GetSignatureType()) {
	case "identity":
		opts = append(opts, aws.WithIdentitySignature())
	case "pkcs7":
		logger.Warn("Vault AWS EC2 auth signatureType 'pkcs7' is deprecated as it relies on SHA-1; use 'rsa2048' instead")

		opts = append(opts, aws.WithPKCS7Signature())
	default:
		opts = append(opts, aws.WithRSA2048Signature())
	}

	return aws.NewAWSAuth(opts...)
}

// Vault manages a Vault API client and handles automatic token renewal.
type Vault struct {
	Client     *vaultapi.Client
	AuthMethod vaultapi.AuthMethod
	Logger     *zap.Logger
}

func New(cfg config.VaultConfig, logger *zap.Logger) (*Vault, error) {
	apiConfig := vaultapi.DefaultConfig()
	apiConfig.Address = cfg.Address

	//nolint:revive // unchecked-type-assertion: transport type guaranteed by DefaultConfig
	transport := apiConfig.HttpClient.Transport.(*http.Transport)
	// Enforce TLS 1.3 for the Vault client, which carries all CA signing requests.
	// Vault's DefaultConfig sets only a TLS 1.2 minimum.
	transport.TLSClientConfig.MinVersion = tls.VersionTLS13

	if cfg.CABundleFile != "" {
		if err := apiConfig.ConfigureTLS(&vaultapi.TLSConfig{
			CACert: cfg.CABundleFile,
		}); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
	}

	client, err := vaultapi.NewClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	v := &Vault{Client: client, Logger: logger}

	client.SetNamespace(cfg.Namespace)

	if cfg.Auth.Token != "" {
		client.SetToken(cfg.Auth.Token)

		return v, nil
	}

	authMethod, err := newVaultAuthMethod(&cfg.Auth, logger)
	// No auth method configured — Vault SDK falls back to VAULT_TOKEN environment variable
	if errors.Is(err, errVaultAuthMethodNotConfigured) {
		return v, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create Vault auth method: %w", err)
	}

	v.AuthMethod = authMethod

	return v, nil
}

// RunTokenRenewalLoop runs the token lifecycle watcher and login loop until context is canceled.
// Whenever the token expires or renewal fails, it re-logins using the configured auth method and
// starts the token lifecycle watcher again with the new token. If login fails, it retries after a delay.
func (v *Vault) RunTokenRenewalLoop(ctx context.Context, secret *vaultapi.Secret) {
	for {
		if err := v.watchTokenLifecycle(ctx, secret); err != nil {
			if ctx.Err() != nil {
				return
			}

			v.Logger.Error("Failed to watch Vault token lifecycle, will retry later", zap.Error(err))
		}

		secret = v.LoginWithRetry(ctx)
		if ctx.Err() != nil {
			return
		}
	}
}

func (v *Vault) LoginWithRetry(ctx context.Context) *vaultapi.Secret {
	for {
		secret, err := v.Client.Auth().Login(ctx, v.AuthMethod)
		if err == nil {
			v.Logger.Info("Successfully login to Vault")

			return secret
		}

		v.Logger.Error("Failed to login to Vault, will retry later", zap.Error(err))

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(loginRetryInterval):
		}
	}
}

func (v *Vault) watchTokenLifecycle(ctx context.Context, secret *vaultapi.Secret) error {
	watcher, err := v.Client.NewLifetimeWatcher(&vaultapi.LifetimeWatcherInput{
		Secret: secret,
	})
	if err != nil {
		return fmt.Errorf("failed to create Vault token lifetime watcher: %w", err)
	}

	v.Logger.Info("Start Vault token lifetime watcher")

	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-watcher.DoneCh():
			if err != nil {
				v.Logger.Error("Failed to renew Vault token, re-attempting login", zap.Error(err))

				return nil
			}

			v.Logger.Info("Vault token can no longer be renewed, re-attempting login")

			return nil
		case info := <-watcher.RenewCh():
			v.Logger.Info("Successfully renewed Vault token", zap.Time("renewed_at", info.RenewedAt))
		}
	}
}
