// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	vaultapi "github.com/hashicorp/vault/api"

	"gateway/internal/config"
	"gateway/internal/vault"
)

func generateCA(t *testing.T) tls.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "acme.int CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{derBytes}, PrivateKey: privateKey}
}

func caPool(t *testing.T, ca tls.Certificate) *x509.CertPool {
	t.Helper()

	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return pool
}

// failingSigner presents a valid public key but refuses to sign.
type failingSigner struct {
	pub crypto.PublicKey
}

func (s failingSigner) Public() crypto.PublicKey { return s.pub }

func (s failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("sign failed")
}

func TestLocalIssuer_load_SignalsOnlyOnCAChange(t *testing.T) {
	ca := generateCA(t)
	file := createKeyPair(t, ca)

	issuer, err := newLocalIssuer(
		&config.TLSLocalIssuerConfig{CertificateFile: file.CertificateFile, PrivateKeyFile: file.PrivateKeyFile},
		keyConfig{typ: keyTypeECDSA, bits: 256},
		defaultCertTTL,
		zap.NewNop(),
	)
	require.NoError(t, err)

	// The reloader loads again when it starts watching, which is not a rotation.
	require.NoError(t, issuer.load())
	assert.Empty(t, issuer.rotated(), "reloading the same CA should not signal a rotation")

	replaceKeyPair(t, file, generateCA(t))
	require.NoError(t, issuer.load())
	assert.Len(t, issuer.rotated(), 1, "a different CA should signal a rotation")

	// A second rotation while the first is unread stays a single notification.
	replaceKeyPair(t, file, generateCA(t))
	require.NoError(t, issuer.load())
	assert.Len(t, issuer.rotated(), 1)
}

func TestLocalIssuer_load_Errors(t *testing.T) {
	valid := createKeyPair(t, generateCA(t))
	other := createKeyPair(t, generateCA(t))
	nonCA := createKeyPair(t, generateCert(t))

	corruptCert := filepath.Join(t.TempDir(), "corrupt.crt")
	require.NoError(t, os.WriteFile(corruptCert, []byte("not a certificate"), 0o600))

	tests := []struct {
		name        string
		cfg         config.TLSLocalIssuerConfig
		wantErr     error
		errContains string
	}{
		{
			name:        "missing files",
			cfg:         config.TLSLocalIssuerConfig{CertificateFile: "missing.crt", PrivateKeyFile: "missing.key"},
			errContains: "failed to load CA key pair",
		},
		{
			name:        "unparseable certificate",
			cfg:         config.TLSLocalIssuerConfig{CertificateFile: corruptCert, PrivateKeyFile: valid.PrivateKeyFile},
			errContains: "failed to load CA key pair",
		},
		{
			name:        "mismatched certificate and key",
			cfg:         config.TLSLocalIssuerConfig{CertificateFile: valid.CertificateFile, PrivateKeyFile: other.PrivateKeyFile},
			errContains: "failed to load CA key pair",
		},
		{
			name:        "certificate is not a CA",
			cfg:         config.TLSLocalIssuerConfig(nonCA),
			wantErr:     errNotCACertificate,
			errContains: nonCA.CertificateFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newLocalIssuer(&tt.cfg, keyConfig{typ: keyTypeECDSA, bits: 256}, defaultCertTTL, zap.NewNop())
			require.Error(t, err)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			}

			if tt.errContains != "" {
				assert.Contains(t, err.Error(), tt.errContains)
			}
		})
	}
}

func TestLocalIssuer_issue(t *testing.T) {
	ca := generateCA(t)
	file := createKeyPair(t, ca)

	issuer, err := newLocalIssuer(
		&config.TLSLocalIssuerConfig{CertificateFile: file.CertificateFile, PrivateKeyFile: file.PrivateKeyFile},
		keyConfig{typ: keyTypeECDSA, bits: 256},
		defaultCertTTL,
		zap.NewNop(),
	)
	require.NoError(t, err)

	issued, err := issuer.issue(t.Context(), []string{"app.acme.int", "10.0.0.5", "alt.acme.int", "::1"})
	require.NoError(t, err)

	key, ok := issued.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected an ECDSA leaf key")
	assert.Equal(t, 256, key.Params().BitSize)

	assert.Equal(t, "app.acme.int", issued.Leaf.Subject.CommonName)
	assert.Equal(t, []string{"app.acme.int", "alt.acme.int"}, issued.Leaf.DNSNames)

	var gotIPs []string
	for _, ip := range issued.Leaf.IPAddresses {
		gotIPs = append(gotIPs, ip.String())
	}

	assert.Equal(t, []string{"10.0.0.5", "::1"}, gotIPs)

	_, err = issued.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "app.acme.int",
		Roots:     caPool(t, ca),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err)
}

func TestLocalIssuer_issue_Errors(t *testing.T) {
	t.Run("key generation fails", func(t *testing.T) {
		cfg := config.TLSLocalIssuerConfig(createKeyPair(t, generateCA(t)))

		// An invalid key config pass
		issuer, err := newLocalIssuer(&cfg, keyConfig{typ: keyTypeECDSA, bits: 128}, defaultCertTTL, zap.NewNop())
		require.NoError(t, err)

		_, err = issuer.issue(t.Context(), []string{"app.acme.int"})
		require.ErrorIs(t, err, errUnsupportedKeyBits)
		assert.Contains(t, err.Error(), "failed to generate leaf key")
	})

	t.Run("CA key fails to sign", func(t *testing.T) {
		ca := generateCA(t)

		caCert, err := x509.ParseCertificate(ca.Certificate[0])
		require.NoError(t, err)

		issuer := &localIssuer{
			key:    keyConfig{typ: keyTypeECDSA, bits: 256},
			ttl:    defaultCertTTL,
			caCert: caCert,
			caKey:  failingSigner{pub: caCert.PublicKey},
		}

		_, err = issuer.issue(t.Context(), []string{"app.acme.int"})
		require.ErrorContains(t, err, "failed to sign leaf certificate")
	})
}

// issueTestCertificate returns leaf, key, and CA PEMs shaped like a Vault PKI
// issue response covering names.
func issueTestCertificate(t *testing.T, names []string) (certPEM, keyPEM, caPEM string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	return certPEM, keyPEM, caPEM
}

// newTestVaultIssuer returns a vaultIssuer whose client talks to a test server
// running handler.
func newTestVaultIssuer(t *testing.T, handler http.HandlerFunc) *vaultIssuer {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	apiConfig := vaultapi.DefaultConfig()
	apiConfig.Address = server.URL
	apiConfig.MaxRetries = 0 // Fail fast on error responses instead of retrying with backoff.

	client, err := vaultapi.NewClient(apiConfig)
	require.NoError(t, err)
	client.SetToken("test-token")

	return &vaultIssuer{
		vault: &vault.Vault{Client: client, Logger: zap.NewNop()},
		mount: "pki",
		role:  "test-role",
		ttl:   24 * time.Hour,
	}
}

type mockAuthMethod struct {
	secret *vaultapi.Secret
}

// Login fails once the context is canceled so RunTokenRenewalLoop can exit
// through LoginWithRetry's ctx.Done branch.
func (m *mockAuthMethod) Login(ctx context.Context, _ *vaultapi.Client) (*vaultapi.Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return m.secret, nil
}

func newTestVault(t *testing.T, authMethod vaultapi.AuthMethod) *vault.Vault {
	t.Helper()

	client, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	require.NoError(t, err)

	client.SetToken("initial-token")

	return &vault.Vault{
		Client:     client,
		AuthMethod: authMethod,
		Logger:     zap.NewNop(),
	}
}

func vaultAuthSecret(clientToken string, leaseDuration int) *vaultapi.Secret {
	return &vaultapi.Secret{
		Auth: &vaultapi.SecretAuth{
			ClientToken:   clientToken,
			LeaseDuration: leaseDuration,
			Renewable:     false, // To avoid calling the Vault renew API during tests
		},
	}
}

func TestVaultIssuer_Issue(t *testing.T) {
	names := []string{"app.example.com", "a.example.com", "b.example.com"}
	certPEM, keyPEM, caPEM := issueTestCertificate(t, names)

	issuer := newTestVaultIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/pki/issue/test-role", r.URL.Path)

		var payload map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		assert.Equal(t, "app.example.com", payload["common_name"])
		assert.Equal(t, "a.example.com,b.example.com", payload["alt_names"])
		assert.Equal(t, "24h0m0s", payload["ttl"])

		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"certificate": certPEM,
			"private_key": keyPEM,
			"ca_chain":    []string{caPEM},
		}})
	})

	cert, err := issuer.issue(t.Context(), names)
	require.NoError(t, err)
	require.NotNil(t, cert.Leaf)
	assert.Equal(t, names, cert.Leaf.DNSNames)
	assert.Len(t, cert.Certificate, 2)
}

func TestVaultIssuer_Issue_IPSANs(t *testing.T) {
	tests := []struct {
		name        string
		names       []string
		wantPayload map[string]any
	}{
		{
			// The no-SNI local-address fallback requests the dialed IP alone;
			// Vault covers an IP common name in the IP SANs itself.
			name:        "bare ip host",
			names:       []string{"10.0.0.5"},
			wantPayload: map[string]any{"common_name": "10.0.0.5", "ttl": "24h0m0s"},
		},
		{
			name:        "dns host with ip alias",
			names:       []string{"app.example.com", "10.0.0.5", "a.example.com"},
			wantPayload: map[string]any{"common_name": "app.example.com", "ttl": "24h0m0s", "alt_names": "a.example.com", "ip_sans": "10.0.0.5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPEM, keyPEM, caPEM := issueTestCertificate(t, tt.names)

			issuer := newTestVaultIssuer(t, func(w http.ResponseWriter, r *http.Request) {
				var payload map[string]any
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
				assert.Equal(t, tt.wantPayload, payload)

				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
					"certificate": certPEM,
					"private_key": keyPEM,
					"ca_chain":    []string{caPEM},
				}})
			})

			_, err := issuer.issue(t.Context(), tt.names)
			require.NoError(t, err)
		})
	}
}

func TestVaultIssuer_Issue_IssuingCAFallback(t *testing.T) {
	certPEM, keyPEM, caPEM := issueTestCertificate(t, []string{"app.example.com"})

	issuer := newTestVaultIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"certificate": certPEM,
			"private_key": keyPEM,
			"issuing_ca":  caPEM,
		}})
	})

	cert, err := issuer.issue(t.Context(), []string{"app.example.com"})
	require.NoError(t, err)
	assert.Len(t, cert.Certificate, 2)
}

func TestVaultIssuer_Issue_Error(t *testing.T) {
	certPEM, keyPEM, _ := issueTestCertificate(t, []string{"app.example.com"})

	tests := []struct {
		name         string
		responseData map[string]any // nil sends {"data": null}
		wantErr      error
	}{
		{name: "null data", responseData: nil, wantErr: errVaultIssueFailed},
		{name: "missing certificate", responseData: map[string]any{"private_key": keyPEM}, wantErr: errVaultIssueFailed},
		{name: "empty certificate", responseData: map[string]any{"certificate": "", "private_key": keyPEM}, wantErr: errVaultIssueFailed},
		{name: "missing private key", responseData: map[string]any{"certificate": certPEM}, wantErr: errVaultIssueFailed},
		{name: "unparseable certificate", responseData: map[string]any{"certificate": "garbage", "private_key": keyPEM}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := newTestVaultIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": tt.responseData})
			})

			_, err := issuer.issue(t.Context(), []string{"app.example.com"})
			require.Error(t, err)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestVaultIssuer_Issue_RequestFails(t *testing.T) {
	issuer := newTestVaultIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := issuer.issue(t.Context(), []string{"app.example.com"})
	require.Error(t, err)
	assert.NotErrorIs(t, err, errVaultIssueFailed)
}

func TestVaultIssuer_Run_LoginsInBackground(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		secret := vaultAuthSecret("login-token", 60)
		issuer := &vaultIssuer{vault: newTestVault(t, &mockAuthMethod{secret: secret})}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		issuer.run(ctx)
		synctest.Wait()

		assert.Equal(t, "login-token", issuer.vault.Client.Token())
	})
}

func TestVaultIssuer_Run_NoAuthMethod(t *testing.T) {
	issuer := &vaultIssuer{vault: newTestVault(t, nil)}

	issuer.run(t.Context())

	assert.Equal(t, "initial-token", issuer.vault.Client.Token())
}
