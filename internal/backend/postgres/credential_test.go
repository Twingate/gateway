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

func TestPasswordCredentials_Credential(t *testing.T) {
	passwordFile := filepath.Join(t.TempDir(), "password")
	require.NoError(t, os.WriteFile(passwordFile, []byte("from file\n"), 0o600))

	tests := []struct {
		name            string
		configured      gatewayconfig.PostgreSQLCredential
		credential      string
		wantPassword    string
		wantCertificate bool
		wantErrContains string
	}{
		{
			name:         "inline password",
			configured:   gatewayconfig.PostgreSQLCredential{Name: testCredential, Password: "secret"},
			credential:   testCredential,
			wantPassword: "secret",
		},
		{
			name:         "password from file",
			configured:   gatewayconfig.PostgreSQLCredential{Name: testCredential, PasswordFile: passwordFile},
			credential:   testCredential,
			wantPassword: "from file",
		},
		{
			name:            "client certificate",
			configured:      gatewayconfig.PostgreSQLCredential{Name: testCredential, Password: "secret", ClientCertificateFile: testCertificateFile, ClientPrivateKeyFile: testPrivateKeyFile},
			credential:      testCredential,
			wantPassword:    "secret",
			wantCertificate: true,
		},
		{
			name:            "unknown credential",
			configured:      gatewayconfig.PostgreSQLCredential{Name: testCredential, Password: "secret"},
			credential:      "other",
			wantErrContains: `unknown credential: "other"`,
		},
		{
			name:            "missing password file",
			configured:      gatewayconfig.PostgreSQLCredential{Name: testCredential, PasswordFile: filepath.Join(t.TempDir(), "missing")},
			credential:      testCredential,
			wantErrContains: "failed to read password file",
		},
		{
			name:            "unreadable client certificate",
			configured:      gatewayconfig.PostgreSQLCredential{Name: testCredential, Password: "secret", ClientCertificateFile: filepath.Join(t.TempDir(), "missing.crt"), ClientPrivateKeyFile: testPrivateKeyFile},
			credential:      testCredential,
			wantErrContains: "failed to load client certificate",
		},
		{
			name:            "invalid client certificate pair",
			configured:      gatewayconfig.PostgreSQLCredential{Name: testCredential, Password: "secret", ClientCertificateFile: testCertificateFile, ClientPrivateKeyFile: testCertificateFile},
			credential:      testCredential,
			wantErrContains: "failed to load client certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credentials := newPasswordCredentials([]gatewayconfig.PostgreSQLCredential{tt.configured})

			got, err := credentials.credential(t.Context(), token.Auth{Password: &token.PasswordAuth{Credential: tt.credential}})

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
