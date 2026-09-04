// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/config"
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
			name:    "certificate is not a CA",
			cfg:     config.TLSLocalIssuerConfig(nonCA),
			wantErr: errNotCACertificate,
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
