// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/config"
)

func TestReloader_run(t *testing.T) {
	fooCert := generateCert(t, "foo.acme.int")
	barCert := generateCert(t, "bar.acme.int")
	fooKeyPair := createKeyPair(t, fooCert)
	barKeyPair := createKeyPair(t, barCert)

	r := newReloader([]config.TLSCertificateFileKeyPair{fooKeyPair, barKeyPair}, zap.NewNop())
	r.run(t.Context())

	requireCert(t, r, "foo.acme.int", fooCert)
	requireCert(t, r, "bar.acme.int", barCert)

	newBarCert := generateCert(t, "bar.acme.int")
	replaceKeyPair(t, barKeyPair, newBarCert)

	requireCert(t, r, "bar.acme.int", newBarCert)
	requireCert(t, r, "foo.acme.int", fooCert)
}

func TestReloader_load(t *testing.T) {
	cert := generateCert(t)
	keyPair := createKeyPair(t, cert)
	otherKeyPair := createKeyPair(t, generateCert(t))

	tests := []struct {
		name    string
		keyPair config.TLSCertificateFileKeyPair
		wantErr bool
	}{
		{name: "valid cert and key", keyPair: keyPair},
		{
			name:    "mismatched cert and key",
			keyPair: config.TLSCertificateFileKeyPair{CertificateFile: keyPair.CertificateFile, PrivateKeyFile: otherKeyPair.PrivateKeyFile},
			wantErr: true,
		},
		{
			name:    "missing files",
			keyPair: config.TLSCertificateFileKeyPair{CertificateFile: "nonexistent.crt", PrivateKeyFile: "nonexistent.key"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newReloader([]config.TLSCertificateFileKeyPair{tt.keyPair}, zap.NewNop())

			err := r.load(tt.keyPair)

			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestReloader_match(t *testing.T) {
	fooCert := generateCert(t, "foo.acme.int")
	barCert := generateCert(t, "bar.acme.int")

	fooKeyPair := createKeyPair(t, fooCert)
	barKeyPair := createKeyPair(t, barCert)

	missing := config.TLSCertificateFileKeyPair{CertificateFile: "nonexistent.crt", PrivateKeyFile: "nonexistent.key"}

	r := newReloader([]config.TLSCertificateFileKeyPair{missing, fooKeyPair, barKeyPair}, zap.NewNop())
	require.NoError(t, r.load(fooKeyPair))
	require.NoError(t, r.load(barKeyPair))
	require.Error(t, r.load(missing))

	tests := []struct {
		name       string
		serverName string
		want       [][]byte
	}{
		{name: "matching SNI", serverName: "bar.acme.int", want: barCert.Certificate},
		{name: "no SNI matches the first loaded certificate", serverName: "", want: fooCert.Certificate},
		{name: "unmatched SNI matches nothing", serverName: "other.acme.int"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.match(clientHello(tt.serverName))

			if tt.want == nil {
				assert.Nil(t, got)

				return
			}

			require.NotNil(t, got)
			assert.Equal(t, tt.want, got.Certificate)
		})
	}
}

func TestReloader_first(t *testing.T) {
	fooCert := generateCert(t, "foo.acme.int")
	fooKeyPair := createKeyPair(t, fooCert)

	missing := config.TLSCertificateFileKeyPair{CertificateFile: "nonexistent.crt", PrivateKeyFile: "nonexistent.key"}

	tests := []struct {
		name     string
		keyPairs []config.TLSCertificateFileKeyPair
		want     [][]byte
	}{
		{
			name:     "skips key pairs that failed to load",
			keyPairs: []config.TLSCertificateFileKeyPair{missing, fooKeyPair},
			want:     fooCert.Certificate,
		},
		{name: "no certificates configured"},
		{
			name: "all certificates failed to load",
			keyPairs: []config.TLSCertificateFileKeyPair{
				missing,
				{CertificateFile: "another-nonexistent.crt", PrivateKeyFile: "another-nonexistent.key"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newReloader(tt.keyPairs, zap.NewNop())
			for _, keyPair := range tt.keyPairs {
				_ = r.load(keyPair)
			}

			got := r.first()

			if tt.want == nil {
				assert.Nil(t, got)

				return
			}

			require.NotNil(t, got)
			assert.Equal(t, tt.want, got.Certificate)
		})
	}
}

func clientHello(serverName string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:        serverName,
		SupportedVersions: []uint16{tls.VersionTLS13},
	}
}

func requireCert(t *testing.T, r *reloader, serverName string, expectedCert tls.Certificate) {
	t.Helper()

	hello := clientHello(serverName)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		existingCert := r.match(hello)

		require.NotNil(c, existingCert)
		require.Equal(c, expectedCert.Certificate, existingCert.Certificate)
	}, time.Second, 5*time.Millisecond, "failed to get certificate for %q", serverName)
}

func generateCert(t *testing.T, dnsNames ...string) tls.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{DNSNames: dnsNames}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}
}

func createKeyPair(t *testing.T, cert tls.Certificate) config.TLSCertificateFileKeyPair {
	t.Helper()

	tmpDir := t.TempDir()

	keyPair := config.TLSCertificateFileKeyPair{
		CertificateFile: filepath.Join(tmpDir, "tls.crt"),
		PrivateKeyFile:  filepath.Join(tmpDir, "tls.key"),
	}
	replaceKeyPair(t, keyPair, cert)

	return keyPair
}

func replaceKeyPair(t *testing.T, keyPair config.TLSCertificateFileKeyPair, newCert tls.Certificate) {
	t.Helper()

	certData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Certificate[0]})
	keyData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(newCert.PrivateKey.(*rsa.PrivateKey))})

	require.NoError(t, os.WriteFile(keyPair.CertificateFile, certData, 0600))
	require.NoError(t, os.WriteFile(keyPair.PrivateKeyFile, keyData, 0600))
}
