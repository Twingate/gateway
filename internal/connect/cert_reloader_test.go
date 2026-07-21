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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestCertReloader_load(t *testing.T) {
	cert := generateCert(t)
	certFile, keyFile := createCertFiles(t, cert)
	_, otherKeyFile := createCertFiles(t, generateCert(t))

	tests := []struct {
		name     string
		certFile string
		keyFile  string
		wantErr  bool
	}{
		{name: "valid cert and key", certFile: certFile, keyFile: keyFile},
		{name: "mismatched cert and key", certFile: certFile, keyFile: otherKeyFile, wantErr: true},
		{name: "missing files", certFile: "nonexistent.crt", keyFile: "nonexistent.key", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := NewCertReloader(tt.certFile, tt.keyFile, zap.NewNop())

			if tt.wantErr {
				require.Error(t, cr.load())

				return
			}

			require.NoError(t, cr.load())

			got, err := cr.GetCertificate(&tls.ClientHelloInfo{})
			require.NoError(t, err)
			assert.Equal(t, cert.Certificate, got.Certificate)
		})
	}
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
