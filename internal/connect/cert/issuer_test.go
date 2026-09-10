// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
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
	"net"
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

func generateKey(t *testing.T) crypto.Signer {
	t.Helper()

	key, err := keyConfig{typ: keyTypeECDSA, bits: 256}.generate()
	require.NoError(t, err)

	return key
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
			_, err := newLocalIssuer(&tt.cfg, zap.NewNop())
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

func TestLocalIssuer_sign(t *testing.T) {
	ca := generateCA(t)
	file := createKeyPair(t, ca)

	issuer, err := newLocalIssuer(
		&config.TLSLocalIssuerConfig{CertificateFile: file.CertificateFile, PrivateKeyFile: file.PrivateKeyFile},
		zap.NewNop(),
	)
	require.NoError(t, err)

	key := generateKey(t)

	req := newCertificateRequest(key, "app.acme.int", defaultTTL)

	leaf, caChain, err := issuer.sign(t.Context(), req)
	require.NoError(t, err)

	assert.Empty(t, leaf.Subject.CommonName)
	assert.Equal(t, []string{"app.acme.int"}, leaf.DNSNames)
	assert.Empty(t, leaf.IPAddresses)

	requested, ok := key.Public().(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, requested.Equal(leaf.PublicKey), "the leaf should carry the requested public key")
	assert.WithinDuration(t, time.Now().Add(defaultTTL), leaf.NotAfter, time.Minute)
	assert.True(t, leaf.NotBefore.Before(time.Now()), "the leaf should already be valid, to absorb clock skew")

	require.Len(t, caChain, 1)
	assert.Equal(t, ca.Certificate[0], caChain[0].Raw)
}

func TestLocalIssuer_sign_CAKeyFails(t *testing.T) {
	ca := generateCA(t)

	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	require.NoError(t, err)

	issuer := &localIssuer{caCert: caCert, caKey: failingSigner{pub: caCert.PublicKey}}

	req := newCertificateRequest(generateKey(t), "app.acme.int", defaultTTL)

	_, _, err = issuer.sign(t.Context(), req)
	require.ErrorContains(t, err, "failed to sign leaf certificate")
}

func signTestCSR(t *testing.T, ca tls.Certificate, csrPEM string) string {
	t.Helper()

	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block, "request payload should carry a PEM CSR")

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, ca.PrivateKey)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func csrPEM(t *testing.T, csr []byte) string {
	t.Helper()

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
}

func caPEM(t *testing.T, ca tls.Certificate) string {
	t.Helper()

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate[0]}))
}

// decodeVaultSignPayload returns the CSR from the request payload and the remaining payload.
func decodeVaultSignPayload(t *testing.T, r *http.Request) (csr string, payload map[string]any) {
	t.Helper()

	require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))

	csr, ok := payload["csr"].(string)
	require.True(t, ok && csr != "", "request payload should carry a CSR")
	delete(payload, "csr")

	return csr, payload
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
	}
}

type mockAuthMethod struct {
	secret *vaultapi.Secret
	err    error
}

func (m *mockAuthMethod) Login(ctx context.Context, _ *vaultapi.Client) (*vaultapi.Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if m.err != nil {
		return nil, m.err
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

func TestVaultIssuer_sign(t *testing.T) {
	ca := generateCA(t)

	issuer := newTestVaultIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/pki/sign/test-role", r.URL.Path)

		csr, payload := decodeVaultSignPayload(t, r)
		assert.Equal(t, map[string]any{"ttl": "24h0m0s", "format": "pem_bundle"}, payload)

		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"certificate": signTestCSR(t, ca, csr) + caPEM(t, ca),
		}})
	})

	leaf, caChain, err := issuer.sign(t.Context(), newCertificateRequest(generateKey(t), "app.acme.int", defaultTTL))
	require.NoError(t, err)
	assert.Equal(t, []string{"app.acme.int"}, leaf.DNSNames)
	assert.Len(t, caChain, 1)
}

func TestVaultIssuer_sign_LeafOnlyBundle(t *testing.T) {
	ca := generateCA(t)

	issuer := newTestVaultIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		csr, _ := decodeVaultSignPayload(t, r)

		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"certificate": signTestCSR(t, ca, csr),
		}})
	})

	leaf, caChain, err := issuer.sign(t.Context(), newCertificateRequest(generateKey(t), "app.acme.int", defaultTTL))
	require.NoError(t, err)
	assert.Equal(t, []string{"app.acme.int"}, leaf.DNSNames)
	assert.Empty(t, caChain)
}

func TestVaultIssuer_sign_Error(t *testing.T) {
	ca := generateCA(t)

	tests := []struct {
		name         string
		responseData map[string]any // nil sends no response body
		wantErr      error
	}{
		{name: "no response body", responseData: nil, wantErr: errVaultIssueFailed},
		{name: "missing certificate", responseData: map[string]any{"expiration": 1}, wantErr: errVaultIssueFailed},
		{name: "empty certificate", responseData: map[string]any{"certificate": ""}, wantErr: errVaultIssueFailed},
		{name: "unparseable certificate", responseData: map[string]any{"certificate": "garbage"}, wantErr: errCertChainNotPEM},
		{name: "blank certificate", responseData: map[string]any{"certificate": " \n "}, wantErr: errCertChainNotPEM},
		{
			name:         "certificate does not match the request",
			responseData: map[string]any{"certificate": caPEM(t, ca)},
			wantErr:      errIssuedCertMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := newTestVaultIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
				if tt.responseData == nil {
					w.WriteHeader(http.StatusNoContent)

					return
				}

				_ = json.NewEncoder(w).Encode(map[string]any{"data": tt.responseData})
			})

			_, _, err := issuer.sign(t.Context(), newCertificateRequest(generateKey(t), "app.acme.int", defaultTTL))
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestVaultIssuer_sign_RequestFails(t *testing.T) {
	issuer := newTestVaultIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, _, err := issuer.sign(t.Context(), newCertificateRequest(generateKey(t), "app.acme.int", defaultTTL))
	require.Error(t, err)
	assert.NotErrorIs(t, err, errVaultIssueFailed)
}

func TestVaultIssuer_run_Login(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		secret := vaultAuthSecret("login-token", 60)
		issuer := &vaultIssuer{vault: newTestVault(t, &mockAuthMethod{secret: secret})}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		err := issuer.run(ctx)
		require.NoError(t, err)
		synctest.Wait()

		assert.Equal(t, "login-token", issuer.vault.Client.Token())
	})
}

func TestVaultIssuer_run_NoAuthMethod(t *testing.T) {
	issuer := &vaultIssuer{vault: newTestVault(t, nil)}

	require.NoError(t, issuer.run(t.Context()))

	assert.Equal(t, "initial-token", issuer.vault.Client.Token())
}

func TestVaultIssuer_run_LoginError(t *testing.T) {
	issuer := &vaultIssuer{vault: newTestVault(t, &mockAuthMethod{err: errors.New("permission denied")})}

	err := issuer.run(t.Context())
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to login to Vault")
}

func TestVerifyIssuedCertificate(t *testing.T) {
	key, otherKey := generateKey(t), generateKey(t)
	req := &certificateRequest{
		key:         key,
		dnsNames:    []string{"foo.acme.int", "bar.acme.int"},
		ipAddresses: []net.IP{net.ParseIP("10.0.0.5")},
		ttl:         defaultTTL,
	}

	tests := []struct {
		name    string
		leaf    *x509.Certificate
		wantErr bool
	}{
		{
			name: "certificate covers requested",
			leaf: &x509.Certificate{
				PublicKey:   key.Public(),
				DNSNames:    []string{"foo.acme.int", "bar.acme.int"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.5")},
				NotAfter:    time.Now().Add(defaultTTL),
			},
		},
		{
			name: "dns name order and casing does not matter",
			leaf: &x509.Certificate{
				PublicKey:   key.Public(),
				DNSNames:    []string{"BAR.ACME.INT", "foo.acme.int"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.5")},
				NotAfter:    time.Now().Add(defaultTTL),
			},
		},
		{
			name: "extra granted name",
			leaf: &x509.Certificate{
				PublicKey:   key.Public(),
				DNSNames:    []string{"foo.acme.int", "bar.acme.int", "extra.acme.int"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.5")},
				NotAfter:    time.Now().Add(defaultTTL),
			},
			wantErr: true,
		},
		{
			name: "extra granted IP",
			leaf: &x509.Certificate{
				PublicKey:   key.Public(),
				DNSNames:    []string{"foo.acme.int", "bar.acme.int"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("10.0.0.6")},
				NotAfter:    time.Now().Add(defaultTTL),
			},
			wantErr: true,
		},
		{
			name: "missing requested dns names",
			leaf: &x509.Certificate{
				PublicKey:   key.Public(),
				IPAddresses: []net.IP{net.ParseIP("10.0.0.5")},
				NotAfter:    time.Now().Add(defaultTTL),
			},
			wantErr: true,
		},
		{
			name: "wrong public key",
			leaf: &x509.Certificate{
				PublicKey:   otherKey.Public(),
				DNSNames:    []string{"foo.acme.int", "bar.acme.int"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.5")},
				NotAfter:    time.Now().Add(defaultTTL),
			},
			wantErr: true,
		},
		{
			name: "validity exceeds requested ttl",
			leaf: &x509.Certificate{
				PublicKey:   key.Public(),
				DNSNames:    []string{"foo.acme.int", "bar.acme.int"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.5")},
				NotAfter:    time.Now().Add(2 * defaultTTL),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyIssuedCertificate(tt.leaf, req)
			if !tt.wantErr {
				assert.NoError(t, err)

				return
			}

			assert.ErrorIs(t, err, errIssuedCertMismatch)
		})
	}
}

func TestParseCertificateChain(t *testing.T) {
	ca := generateCA(t)

	der, err := newCertificateRequest(generateKey(t), "app.acme.int", defaultTTL).csr()
	require.NoError(t, err)

	tests := []struct {
		name    string
		pems    []string
		wantLen int
		wantErr error
	}{
		{
			name:    "multiple entries, each holding one or more certificate",
			pems:    []string{signTestCSR(t, ca, csrPEM(t, der)) + "\n\n" + caPEM(t, ca), caPEM(t, ca) + "\n\n"},
			wantLen: 3,
		},
		{
			name:    "not PEM at all",
			pems:    []string{"garbage"},
			wantErr: errCertChainNotPEM,
		},
		{
			name:    "PEM block is not a certificate",
			pems:    []string{csrPEM(t, der)},
			wantErr: errCertChainNotPEM,
		},
		{
			name:    "whitespace only",
			pems:    []string{" \n "},
			wantErr: errCertChainNotPEM,
		},
		{
			name:    "no entries",
			pems:    nil,
			wantErr: errCertChainNotPEM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain, err := parseCertificateChain(tt.pems)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Len(t, chain, tt.wantLen)
		})
	}
}

func TestParseCertificateChain_UnparseableCertificate(t *testing.T) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})

	_, err := parseCertificateChain([]string{string(certPEM)})
	require.ErrorContains(t, err, "failed to parse issued certificate")
}
