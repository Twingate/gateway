// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

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

func TestCertReloader_Run(t *testing.T) {
	fooCert := generateCert(t, "foo.acme.int")
	barCert := generateCert(t, "bar.acme.int")
	fooFile := createCertFiles(t, fooCert)
	barFile := createCertFiles(t, barCert)

	cr := NewCertReloader([]config.TLSCertificateFileKeyPair{fooFile, barFile}, zap.NewNop())
	cr.Run(t.Context())

	requireCert(t, cr, "foo.acme.int", fooCert)
	requireCert(t, cr, "bar.acme.int", barCert)

	newBarCert := generateCert(t, "bar.acme.int")
	replaceCertFiles(t, barFile, newBarCert)

	requireCert(t, cr, "bar.acme.int", newBarCert)
	requireCert(t, cr, "foo.acme.int", fooCert)
}

func TestCertReloader_load(t *testing.T) {
	cert := generateCert(t)
	file := createCertFiles(t, cert)
	otherFile := createCertFiles(t, generateCert(t))

	tests := []struct {
		name    string
		file    config.TLSCertificateFileKeyPair
		wantErr bool
	}{
		{name: "valid cert and key", file: file},
		{
			name:    "mismatched cert and key",
			file:    config.TLSCertificateFileKeyPair{CertificateFile: file.CertificateFile, PrivateKeyFile: otherFile.PrivateKeyFile},
			wantErr: true,
		},
		{
			name:    "missing files",
			file:    config.TLSCertificateFileKeyPair{CertificateFile: "nonexistent.crt", PrivateKeyFile: "nonexistent.key"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := NewCertReloader([]config.TLSCertificateFileKeyPair{tt.file}, zap.NewNop())

			err := cr.load(tt.file)

			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestCertReloader_GetCertificate(t *testing.T) {
	fooCert := generateCert(t, "foo.acme.int")
	barCert := generateCert(t, "bar.acme.int")

	fooFile := createCertFiles(t, fooCert)
	barFile := createCertFiles(t, barCert)

	missing := config.TLSCertificateFileKeyPair{CertificateFile: "nonexistent.crt", PrivateKeyFile: "nonexistent.key"}

	cr := NewCertReloader([]config.TLSCertificateFileKeyPair{missing, fooFile, barFile}, zap.NewNop())
	require.NoError(t, cr.load(fooFile))
	require.NoError(t, cr.load(barFile))
	require.Error(t, cr.load(missing))

	tests := []struct {
		name       string
		serverName string
		want       [][]byte
	}{
		{name: "matching SNI", serverName: "bar.acme.int", want: barCert.Certificate},
		{name: "no SNI serves the first loaded certificate", serverName: "", want: fooCert.Certificate},
		{name: "unmatched SNI falls back to the first loaded certificate", serverName: "other.acme.int", want: fooCert.Certificate},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cr.GetCertificate(clientHello(tt.serverName))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.Certificate)
		})
	}
}

func TestCertReloader_GetCertificate_NoCertificates(t *testing.T) {
	tests := []struct {
		name  string
		files []config.TLSCertificateFileKeyPair
	}{
		{name: "no certificates configured"},
		{
			name: "all certificates failed to load",
			files: []config.TLSCertificateFileKeyPair{
				{CertificateFile: "nonexistent.crt", PrivateKeyFile: "nonexistent.key"},
				{CertificateFile: "another-nonexistent.crt", PrivateKeyFile: "another-nonexistent.key"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := NewCertReloader(tt.files, zap.NewNop())

			for _, file := range tt.files {
				require.Error(t, cr.load(file))
			}

			got, err := cr.GetCertificate(clientHello("bar.acme.int"))
			assert.Nil(t, got)
			require.ErrorIs(t, err, errNoCertificates)
		})
	}
}

func clientHello(serverName string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:        serverName,
		SupportedVersions: []uint16{tls.VersionTLS13},
	}
}

func requireCert(t *testing.T, certReloader *CertReloader, serverName string, expectedCert tls.Certificate) {
	t.Helper()

	hello := clientHello(serverName)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		existingCert, err := certReloader.GetCertificate(hello)
		require.NoError(c, err)

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

func createCertFiles(t *testing.T, cert tls.Certificate) config.TLSCertificateFileKeyPair {
	t.Helper()

	tmpDir := t.TempDir()

	file := config.TLSCertificateFileKeyPair{
		CertificateFile: filepath.Join(tmpDir, "tls.crt"),
		PrivateKeyFile:  filepath.Join(tmpDir, "tls.key"),
	}
	replaceCertFiles(t, file, cert)

	return file
}

func replaceCertFiles(t *testing.T, file config.TLSCertificateFileKeyPair, newCert tls.Certificate) {
	t.Helper()

	certData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Certificate[0]})
	keyData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(newCert.PrivateKey.(*rsa.PrivateKey))})

	require.NoError(t, os.WriteFile(file.CertificateFile, certData, 0600))
	require.NoError(t, os.WriteFile(file.PrivateKeyFile, keyData, 0600))
}
