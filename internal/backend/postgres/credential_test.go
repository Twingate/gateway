// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

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
	awsIAM := &token.AWSIAMAuth{Region: "eu-west-1"}

	tests := []struct {
		name string
		auth token.Auth
		want credentialProvider
	}{
		{
			name: "password",
			auth: passwordAuth,
			want: &passwordCredential{cfg: passwords[testCredential]},
		},
		{
			name: "AWS IAM",
			auth: token.Auth{Type: token.AuthTypeAWSIAM, User: testDatabaseUser, AWSIAM: awsIAM},
			want: &awsIAMCredential{upstreamAddress: "db.acme.int:5432", user: testDatabaseUser, auth: awsIAM},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newCredentialProvider("db.acme.int:5432", tt.auth, passwords)
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("GCP IAM", func(t *testing.T) {
		auth := token.Auth{Type: token.AuthTypeGCPIAM, User: "db@acme-int.iam", GCPIAM: &token.GCPIAMAuth{}}

		got, err := newCredentialProvider("db.acme.int:5432", auth, passwords)
		require.NoError(t, err)

		gcp, ok := got.(*gcpIAMCredential)
		require.True(t, ok, "got %T", got)
		assert.Equal(t, "db@acme-int.iam.gserviceaccount.com", gcp.serviceAccount)
	})
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
			auth:    token.Auth{Type: "kerberos"},
			wantErr: errUnsupportedAuthType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newCredentialProvider("db.acme.int:5432", tt.auth, passwords)

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

// setStaticAWSCredentials keeps the AWS profiles of the machine running the tests out of the
// default configuration.
func setStaticAWSCredentials(t *testing.T) {
	t.Helper()

	emptyFile := filepath.Join(t.TempDir(), "empty")
	require.NoError(t, os.WriteFile(emptyFile, nil, 0o600))

	t.Setenv("AWS_CONFIG_FILE", emptyFile)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", emptyFile)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
}

func TestAWSIAMCredential_Retrieve(t *testing.T) {
	setStaticAWSCredentials(t)

	got, err := newAWSIAMCredential("db.acme.int:5432", testDatabaseUser, &token.AWSIAMAuth{Region: "eu-west-1"}).retrieve(t.Context())
	require.NoError(t, err)

	assert.Nil(t, got.certificate)
	// The token is signed for the upstream, the database user, the access key and the region.
	assert.Contains(t, got.password, "db.acme.int:5432?")
	assert.Contains(t, got.password, "Action=connect")
	assert.Contains(t, got.password, "DBUser="+testDatabaseUser)
	assert.Contains(t, got.password, "X-Amz-Credential=AKIDEXAMPLE")
	assert.Contains(t, got.password, url.QueryEscape("/eu-west-1/rds-db/aws4_request"))
}

func TestAWSIAMCredential_Retrieve_Error(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T)
		auth    *token.AWSIAMAuth
		wantErr error
	}{
		{
			name: "AWS profile not found",
			setup: func(t *testing.T) {
				t.Helper()

				setStaticAWSCredentials(t)
				t.Setenv("AWS_PROFILE", "missing")
			},
			auth:    &token.AWSIAMAuth{Region: "eu-west-1"},
			wantErr: errFailedToLoadAWSConfig,
		},
		{
			// The assumed role's credentials are fetched when the token is signed, so an unreachable
			// STS fails the token build rather than the config load.
			name: "assume role fails",
			setup: func(t *testing.T) {
				t.Helper()

				setStaticAWSCredentials(t)

				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				require.NoError(t, listener.Close())

				t.Setenv("AWS_ENDPOINT_URL_STS", "http://"+listener.Addr().String())
				t.Setenv("AWS_MAX_ATTEMPTS", "1")
			},
			auth:    &token.AWSIAMAuth{Region: "eu-west-1", AssumeRoleARN: "arn:aws:iam::123456789012:role/db"},
			wantErr: errFailedToBuildRDSToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)

			_, err := newAWSIAMCredential("db.acme.int:5432", testDatabaseUser, tt.auth).retrieve(t.Context())

			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

var errTokenSource = errors.New("token source failed")

type failingTokenSource struct{}

func (failingTokenSource) Token() (*oauth2.Token, error) {
	return nil, errTokenSource
}

func TestGCPIAMCredential_Retrieve(t *testing.T) {
	tests := []struct {
		name               string
		impersonate        string
		wantServiceAccount string
	}{
		{name: "database user's service account", wantServiceAccount: "db@acme-int.iam.gserviceaccount.com"},
		{name: "impersonated service account", impersonate: "other@acme-int.iam.gserviceaccount.com", wantServiceAccount: "other@acme-int.iam.gserviceaccount.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := newGCPIAMCredential("db@acme-int.iam", &token.GCPIAMAuth{ImpersonateServiceAccount: tt.impersonate})
			creds.newTokenSource = func(_ context.Context, serviceAccount string) (oauth2.TokenSource, error) {
				return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "token-for-" + serviceAccount}), nil
			}

			got, err := creds.retrieve(t.Context())
			require.NoError(t, err)
			assert.Equal(t, credential{password: "token-for-" + tt.wantServiceAccount}, got)
		})
	}
}

func TestGCPIAMCredential_Retrieve_Error(t *testing.T) {
	// Keeps the Application Default Credentials of the machine running the tests out of the lookup.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))

	tests := []struct {
		name           string
		newTokenSource func(context.Context, string) (oauth2.TokenSource, error)
		wantErr        error
	}{
		{
			name:    "credentials not found",
			wantErr: errFailedToLoadGCPCredentials,
		},
		{
			name:           "token fetch fails",
			newTokenSource: func(context.Context, string) (oauth2.TokenSource, error) { return failingTokenSource{}, nil },
			wantErr:        errFailedToFetchGCPToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := newGCPIAMCredential("db@acme-int.iam", &token.GCPIAMAuth{})
			if tt.newTokenSource != nil {
				creds.newTokenSource = tt.newTokenSource
			}

			_, err := creds.retrieve(t.Context())

			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}
