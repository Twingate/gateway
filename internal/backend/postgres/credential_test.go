// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/token"
)

const (
	testCredential      = "test"
	testCertificateFile = "../../../test/data/proxy/tls.crt"
	testPrivateKeyFile  = "../../../test/data/proxy/tls.key"
)

func TestNewCredentialProvider(t *testing.T) {
	passwords := newPasswordCredentials([]gatewayconfig.PostgreSQLCredential{{Name: testCredential, Password: "secret"}})

	got, err := newCredentialProvider(passwordAuth, passwords)
	require.NoError(t, err)

	assert.Equal(t, &passwordCredential{cfg: passwords[testCredential]}, got)
}

func TestNewCredentialProvider_Error(t *testing.T) {
	passwords := newPasswordCredentials([]gatewayconfig.PostgreSQLCredential{{Name: testCredential, Password: "secret"}})

	tests := []struct {
		name    string
		auth    token.Auth
		wantErr error
	}{
		{
			name:    "unknown credential",
			auth:    token.Auth{Type: token.AuthTypePassword, Password: &token.PasswordAuth{Credential: "other"}},
			wantErr: errUnknownCredential,
		},
		{
			name:    "unsupported auth type",
			auth:    token.Auth{Type: token.AuthTypeGCPIAM},
			wantErr: errUnsupportedAuthType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newCredentialProvider(tt.auth, passwords)

			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestPasswordCredential_Retrieve(t *testing.T) {
	passwordFile := filepath.Join(t.TempDir(), "password")
	require.NoError(t, os.WriteFile(passwordFile, []byte("from file\n"), 0o600))

	tests := []struct {
		name            string
		configured      gatewayconfig.PostgreSQLCredential
		wantPassword    string
		wantCertificate bool
		wantErrContains string
	}{
		{
			name:         "inline password",
			configured:   gatewayconfig.PostgreSQLCredential{Name: testCredential, Password: "secret"},
			wantPassword: "secret",
		},
		{
			name:         "password from file",
			configured:   gatewayconfig.PostgreSQLCredential{Name: testCredential, PasswordFile: passwordFile},
			wantPassword: "from file",
		},
		{
			name:            "client certificate",
			configured:      gatewayconfig.PostgreSQLCredential{Name: testCredential, Password: "secret", ClientCertificateFile: testCertificateFile, ClientPrivateKeyFile: testPrivateKeyFile},
			wantPassword:    "secret",
			wantCertificate: true,
		},
		{
			name:            "missing password file",
			configured:      gatewayconfig.PostgreSQLCredential{Name: testCredential, PasswordFile: filepath.Join(t.TempDir(), "missing")},
			wantErrContains: "failed to read password file",
		},
		{
			name:            "unreadable client certificate",
			configured:      gatewayconfig.PostgreSQLCredential{Name: testCredential, Password: "secret", ClientCertificateFile: filepath.Join(t.TempDir(), "missing.crt"), ClientPrivateKeyFile: testPrivateKeyFile},
			wantErrContains: "failed to load client certificate",
		},
		{
			name:            "invalid client certificate pair",
			configured:      gatewayconfig.PostgreSQLCredential{Name: testCredential, Password: "secret", ClientCertificateFile: testCertificateFile, ClientPrivateKeyFile: testCertificateFile},
			wantErrContains: "failed to load client certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (&passwordCredential{cfg: tt.configured}).retrieve(t.Context())

			if tt.wantErrContains != "" {
				require.ErrorContains(t, err, tt.wantErrContains)

				return
			}

			require.NoError(t, err)

			assert.Equal(t, tt.wantPassword, got.password)
			assert.Equal(t, tt.wantCertificate, got.certificate != nil)
		})
	}
}
