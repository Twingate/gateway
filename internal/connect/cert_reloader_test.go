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
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestReloadWhenFileChanged(t *testing.T) {
	oldCert := generateCert(t)
	certFile, keyFile := createCertFiles(t, oldCert)
	certReloader := NewCertReloader(certFile, keyFile, zap.NewNop())
	certReloader.Run(t.Context())

	requireCertReloader(t, certReloader, oldCert)

	newCert := generateCert(t)
	replaceCertFiles(t, certFile, keyFile, newCert)

	hello := &tls.ClientHelloInfo{}

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		cert, err := certReloader.GetCertificate(hello)
		assert.NoError(t, err)

		assert.Equal(c, newCert.Certificate, cert.Certificate)
	}, time.Second, 5*time.Millisecond)
}

func TestDontReloadWhenMismatchedKeyAndCertificate(t *testing.T) {
	expectedCert := generateCert(t)
	certFile, keyFile := createCertFiles(t, expectedCert)
	certReloader := NewCertReloader(certFile, keyFile, zap.NewNop())
	certReloader.Run(t.Context())

	requireCertReloader(t, certReloader, expectedCert)

	// Create mismatched key and certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	invalidCert := tls.Certificate{
		Certificate: expectedCert.Certificate,
		PrivateKey:  privateKey,
	}

	replaceCertFiles(t, certFile, keyFile, invalidCert)
	time.Sleep(5 * time.Millisecond)

	hello := &tls.ClientHelloInfo{}

	cert, err := certReloader.GetCertificate(hello)
	require.NoError(t, err)

	// Ensure certificate is unchanged
	assert.Equal(t, expectedCert.Certificate, cert.Certificate)
}

func TestErrorInitializeCertReloader(t *testing.T) {
	tests := []struct {
		name  string
		setup func(logger *zap.Logger) *CertReloader
	}{
		{
			name: "invalid cert file",
			setup: func(logger *zap.Logger) *CertReloader {
				return NewCertReloader("foo.crt", "../../test/data/proxy/tls.key", logger)
			},
		},
		{
			name: "invalid key file",
			setup: func(logger *zap.Logger) *CertReloader {
				return NewCertReloader("../../test/data/proxy/tls.crt", "foo.key", logger)
			},
		},
		{
			name: "mismatched key and certificate",
			setup: func(logger *zap.Logger) *CertReloader {
				_, keyFile := createCertFiles(t, generateCert(t))

				return NewCertReloader("../../test/data/proxy/tls.crt", keyFile, logger)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				core, logs := observer.New(zapcore.DebugLevel)
				logger := zap.New(core)

				certReloader := tt.setup(logger)
				certReloader.Run(t.Context())

				synctest.Wait()

				log := logs.All()[0]
				assert.Equal(t, zapcore.ErrorLevel, log.Level)
				assert.Equal(t, "failed to watch cert and key file, will retry later", log.Message)
			})
		})
	}
}

func requireCertReloader(t *testing.T, certReloader *CertReloader, expectedCert tls.Certificate) {
	t.Helper()

	hello := &tls.ClientHelloInfo{}

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		existingCert, err := certReloader.GetCertificate(hello)
		require.NoError(c, err)

		require.NotNil(c, existingCert)
		require.Equal(c, expectedCert.Certificate, existingCert.Certificate)
	}, time.Second, 5*time.Millisecond, "failed to get certificate")
}

func generateCert(t *testing.T) tls.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}
}

func createCertFiles(t *testing.T, cert tls.Certificate) (certFile string, keyFile string) {
	t.Helper()

	tmpDir := t.TempDir()

	certFile = filepath.Join(tmpDir, "tls.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	require.NoError(t, os.WriteFile(certFile, certPEM, 0600))

	keyFile = filepath.Join(tmpDir, "tls.key")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey))})
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0600))

	return certFile, keyFile
}

func replaceCertFiles(t *testing.T, certFile, keyFile string, newCert tls.Certificate) {
	t.Helper()

	certData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Certificate[0]})
	keyData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(newCert.PrivateKey.(*rsa.PrivateKey))})

	require.NoError(t, os.WriteFile(certFile, certData, 0600))
	require.NoError(t, os.WriteFile(keyFile, keyData, 0600))
}
