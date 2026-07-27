// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

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

	vault "github.com/hashicorp/vault/api"

	gatewayconfig "gateway/internal/config"
)

var errVaultAuthMethodNotConfigured = errors.New("no Vault auth method configured")

const (
	loginRetryInterval = time.Minute
)

//nolint:ireturn
func newVaultAuthMethod(authConfig *gatewayconfig.SSHCAVaultAuthConfig, logger *zap.Logger) (vault.AuthMethod, error) {
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

func newAppRoleAuthMethod(appRoleConfig *gatewayconfig.SSHCAVaultAppRoleConfig) (*approle.AppRoleAuth, error) {
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

func newGCPAuthMethod(gcpConfig *gatewayconfig.SSHCAVaultGCPConfig) (*gcp.GCPAuth, error) {
	opts := []gcp.LoginOption{
		gcp.WithMountPath(gcpConfig.GetMount()),
	}

	// GCE is the default in the Vault GCP auth SDK
	if strings.EqualFold(gcpConfig.Type, "iam") {
		opts = append(opts, gcp.WithIAMAuth(gcpConfig.ServiceAccountEmail))
	}

	return gcp.NewGCPAuth(gcpConfig.Role, opts...)
}

func newAWSAuthMethod(awsConfig *gatewayconfig.SSHCAVaultAWSConfig, logger *zap.Logger) (*aws.AWSAuth, error) {
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
	client     *vault.Client
	authMethod vault.AuthMethod
	logger     *zap.Logger
}

func newVault(vaultConfig *gatewayconfig.SSHCAVaultConfig, logger *zap.Logger) (*Vault, error) {
	config := vault.DefaultConfig()
	config.Address = vaultConfig.Address

	//nolint:revive // unchecked-type-assertion: transport type guaranteed by DefaultConfig
	transport := config.HttpClient.Transport.(*http.Transport)
	// Enforce TLS 1.3 for the Vault client, which carries all CA signing requests.
	// Vault's DefaultConfig sets only a TLS 1.2 minimum.
	transport.TLSClientConfig.MinVersion = tls.VersionTLS13

	if vaultConfig.CABundleFile != "" {
		if err := config.ConfigureTLS(&vault.TLSConfig{
			CACert: vaultConfig.CABundleFile,
		}); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
	}

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	v := &Vault{client: client, logger: logger}

	client.SetNamespace(vaultConfig.Namespace)

	if vaultConfig.Auth.Token != "" {
		client.SetToken(vaultConfig.Auth.Token)

		return v, nil
	}

	authMethod, err := newVaultAuthMethod(&vaultConfig.Auth, logger)
	// No auth method configured — Vault SDK falls back to VAULT_TOKEN environment variable
	if errors.Is(err, errVaultAuthMethodNotConfigured) {
		return v, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create Vault auth method: %w", err)
	}

	v.authMethod = authMethod

	return v, nil
}

// runTokenRenewalLoop runs the token lifecycle watcher and login loop until context is canceled.
// Whenever the token expires or renewal fails, it re-logins using the configured auth method and
// starts the token lifecycle watcher again with the new token. If login fails, it retries after a delay.
func (v *Vault) runTokenRenewalLoop(ctx context.Context, secret *vault.Secret) {
	for {
		if err := v.watchTokenLifecycle(ctx, secret); err != nil {
			if ctx.Err() != nil {
				return
			}

			v.logger.Error("Failed to watch Vault token lifecycle, will retry later", zap.Error(err))
		}

		secret = v.loginWithRetry(ctx)
		if ctx.Err() != nil {
			return
		}
	}
}

func (v *Vault) watchTokenLifecycle(ctx context.Context, secret *vault.Secret) error {
	watcher, err := v.client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret: secret,
	})
	if err != nil {
		return fmt.Errorf("failed to create Vault token lifetime watcher: %w", err)
	}

	v.logger.Info("Start Vault token lifetime watcher")

	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-watcher.DoneCh():
			if err != nil {
				v.logger.Error("Failed to renew Vault token, re-attempting login", zap.Error(err))

				return nil
			}

			v.logger.Info("Vault token can no longer be renewed, re-attempting login")

			return nil
		case info := <-watcher.RenewCh():
			v.logger.Info("Successfully renewed Vault token", zap.Time("renewed_at", info.RenewedAt))
		}
	}
}

func (v *Vault) loginWithRetry(ctx context.Context) *vault.Secret {
	for {
		secret, err := v.client.Auth().Login(ctx, v.authMethod)
		if err == nil {
			v.logger.Info("Successfully login to Vault")

			return secret
		}

		v.logger.Error("Failed to login to Vault, will retry later", zap.Error(err))

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(loginRetryInterval):
		}
	}
}
