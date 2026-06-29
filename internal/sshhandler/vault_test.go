// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/hashicorp/vault/api/auth/aws"
	"github.com/hashicorp/vault/api/auth/gcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	vault "github.com/hashicorp/vault/api"

	gatewayconfig "gateway/internal/config"
)

func TestNewVault_EnforcesTLS13(t *testing.T) {
	v, err := newVault(&gatewayconfig.SSHCAVaultConfig{
		Address: "https://vault.example.com",
		Auth:    gatewayconfig.SSHCAVaultAuthConfig{Token: "test-token"},
	}, zap.NewNop())
	require.NoError(t, err)

	transport, ok := v.client.CloneConfig().HttpClient.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.TLSClientConfig)
	assert.Equal(t, uint16(tls.VersionTLS13), transport.TLSClientConfig.MinVersion)
}

func TestNewVaultAuthMethod_AppRole(t *testing.T) {
	t.Run("with secretID", func(t *testing.T) {
		cfg := &gatewayconfig.SSHCAVaultAuthConfig{
			AppRole: &gatewayconfig.SSHCAVaultAppRoleConfig{
				RoleID:   "role-id",
				SecretID: "my-secret-id",
				Mount:    "custom-approle",
			},
		}

		authMethod, err := newVaultAuthMethod(cfg)
		require.NoError(t, err)
		require.IsType(t, &approle.AppRoleAuth{}, authMethod)
	})

	t.Run("with secretIDFile", func(t *testing.T) {
		cfg := &gatewayconfig.SSHCAVaultAuthConfig{
			AppRole: &gatewayconfig.SSHCAVaultAppRoleConfig{
				RoleID:       "role-id",
				SecretIDFile: "/path/to/secret-id",
				Mount:        "custom-approle",
			},
		}

		authMethod, err := newVaultAuthMethod(cfg)
		require.NoError(t, err)
		require.IsType(t, &approle.AppRoleAuth{}, authMethod)
	})
}

func TestNewVaultAuthMethod_GCP(t *testing.T) {
	cfg := &gatewayconfig.SSHCAVaultAuthConfig{
		GCP: &gatewayconfig.SSHCAVaultGCPConfig{
			Mount:               "custom-gcp",
			Role:                "my-role",
			Type:                "iam",
			ServiceAccountEmail: "gateway-sa@project.iam.gserviceaccount.com",
		},
	}

	authMethod, err := newVaultAuthMethod(cfg)
	require.NoError(t, err)
	require.IsType(t, &gcp.GCPAuth{}, authMethod)
}

func TestNewVaultAuthMethod_AWS(t *testing.T) {
	t.Run("IAM", func(t *testing.T) {
		cfg := &gatewayconfig.SSHCAVaultAuthConfig{
			AWS: &gatewayconfig.SSHCAVaultAWSConfig{
				Mount:             "custom-aws",
				Role:              "my-role",
				Type:              "iam",
				Region:            "us-west-2",
				IAMServerIDHeader: "my-header-value",
			},
		}

		authMethod, err := newVaultAuthMethod(cfg)
		require.NoError(t, err)
		require.IsType(t, &aws.AWSAuth{}, authMethod)
	})

	t.Run("EC2", func(t *testing.T) {
		cfg := &gatewayconfig.SSHCAVaultAuthConfig{
			AWS: &gatewayconfig.SSHCAVaultAWSConfig{
				Mount:         "custom-aws",
				Role:          "my-role",
				Type:          "ec2",
				SignatureType: "identity",
				Nonce:         "my-nonce",
			},
		}

		authMethod, err := newVaultAuthMethod(cfg)
		require.NoError(t, err)
		require.IsType(t, &aws.AWSAuth{}, authMethod)
	})
}

func TestNewVaultAuthMethod_NoAuth(t *testing.T) {
	cfg := &gatewayconfig.SSHCAVaultAuthConfig{}

	authMethod, err := newVaultAuthMethod(cfg)
	require.ErrorIs(t, err, errVaultAuthMethodNotConfigured)
	require.Nil(t, authMethod)
}

type mockAuthMethod struct {
	mu     sync.Mutex
	secret *vault.Secret
	err    error
}

func (m *mockAuthMethod) Login(ctx context.Context, _ *vault.Client) (*vault.Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	return m.secret, m.err
}

func newTestVault(t *testing.T, authMethod vault.AuthMethod) *Vault {
	t.Helper()

	client, err := vault.NewClient(vault.DefaultConfig())
	require.NoError(t, err)

	client.SetToken("initial-token")

	return &Vault{
		client:     client,
		authMethod: authMethod,
		logger:     zap.NewNop(),
	}
}

func vaultAuthSecret(clientToken string, leaseDuration int) *vault.Secret {
	return &vault.Secret{
		Auth: &vault.SecretAuth{
			ClientToken:   clientToken,
			LeaseDuration: leaseDuration,
			Renewable:     false, // To avoid calling the Vault renew API during tests
		},
	}
}

func TestRunTokenRenewalLoop_LoginAfterTokenExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		secret := vaultAuthSecret("renewed-token", 30)
		v := newTestVault(t, &mockAuthMethod{
			secret: secret,
		})

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		go v.runTokenRenewalLoop(ctx, secret)

		// Advance time past the token's max TTL to exit the watcher and trigger re-login
		time.Sleep(30 * time.Second)
		synctest.Wait()

		require.Equal(t, "renewed-token", v.client.Token())
	})
}

func TestRunTokenRenewalLoop_LoginFailsThenSucceeds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		secret := vaultAuthSecret("renewed-token", 30)
		auth := &mockAuthMethod{
			secret: secret,
			err:    errors.New("login failed"),
		}

		v := newTestVault(t, auth)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		go v.runTokenRenewalLoop(ctx, secret)

		// Wait for the watcher to exit and the first login attempt to fail
		time.Sleep(30 * time.Second)
		synctest.Wait()

		require.Equal(t, "initial-token", v.client.Token())

		// Update mock to succeed on the next attempt
		auth.mu.Lock()
		auth.err = nil
		auth.mu.Unlock()

		// Advance time past the retry interval
		time.Sleep(loginRetryInterval)
		synctest.Wait()

		require.Equal(t, "renewed-token", v.client.Token())
	})
}

func TestRunTokenRenewalLoop_ContextCanceled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		secret := vaultAuthSecret("renewed-token", 30)
		v := newTestVault(t, &mockAuthMethod{
			secret: secret,
		})

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		done := make(chan struct{})

		go func() {
			v.runTokenRenewalLoop(ctx, secret)
			close(done)
		}()

		// Token watcher starts and block on its internal timer
		synctest.Wait()

		// Cancel while the watcher is still running
		cancel()
		synctest.Wait()

		// Wait token renewal goroutine to exit
		<-done

		require.Equal(t, "initial-token", v.client.Token())
	})
}
