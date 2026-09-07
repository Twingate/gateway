// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"crypto/tls"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/config"
)

func testAutomationConfig() *config.TLSAutomationConfig {
	return &config.TLSAutomationConfig{
		Issuer: config.TLSIssuerConfig{
			Local: &config.TLSLocalIssuerConfig{
				CertificateFile: "../../../test/data/proxy/tls.crt",
				PrivateKeyFile:  "../../../test/data/proxy/tls.key",
			},
		},
	}
}

func newTestManager(t *testing.T, tlsCfg config.TLSConfig) *Manager {
	t.Helper()

	service, err := NewManager(tlsCfg, zap.NewNop())
	require.NoError(t, err)

	// Load synchronously instead of waiting on the reloaders.
	if tlsCfg.Certificates != nil {
		for _, file := range tlsCfg.Certificates.Files {
			require.NoError(t, service.certs.load(file))
		}
	}

	return service
}

func leafNames(cert *tls.Certificate) []string {
	names := slices.Clone(cert.Leaf.DNSNames)
	for _, ip := range cert.Leaf.IPAddresses {
		names = append(names, ip.String())
	}

	return names
}

func TestNewManager_AutomationError(t *testing.T) {
	_, err := NewManager(config.TLSConfig{
		Automation: &config.TLSAutomationConfig{
			Issuer: config.TLSIssuerConfig{
				Local: &config.TLSLocalIssuerConfig{CertificateFile: "missing.crt", PrivateKeyFile: "missing.key"},
			},
		},
	}, zap.NewNop())

	assert.ErrorContains(t, err, "failed to create cert automation")
}

func TestManager_GetCertificate(t *testing.T) {
	fooCert := generateCert(t, "foo.acme.int")
	files := &config.TLSCertificateSources{Files: []config.TLSCertificateFileKeyPair{createKeyPair(t, fooCert)}}

	tests := []struct {
		name       string
		tlsCfg     config.TLSConfig
		hello      *tls.ClientHelloInfo
		wantCert   [][]byte
		wantIssued []string
	}{
		{
			name:     "SNI covered by a configured certificate",
			tlsCfg:   config.TLSConfig{Certificates: files, Automation: testAutomationConfig()},
			hello:    clientHello("foo.acme.int"),
			wantCert: fooCert.Certificate,
		},
		{
			name:       "uncovered SNI is issued on demand",
			tlsCfg:     config.TLSConfig{Certificates: files, Automation: testAutomationConfig()},
			hello:      clientHello("other.acme.int"),
			wantIssued: []string{"other.acme.int"},
		},
		{
			name:     "uncovered SNI without automation falls back to a configured certificate",
			tlsCfg:   config.TLSConfig{Certificates: files},
			hello:    clientHello("other.acme.int"),
			wantCert: fooCert.Certificate,
		},
		{
			name:     "no SNI is answered by a configured certificate",
			tlsCfg:   config.TLSConfig{Certificates: files, Automation: testAutomationConfig()},
			hello:    clientHello(""),
			wantCert: fooCert.Certificate,
		},
		{
			name:       "SNI is issued on demand when no certificates are configured at all",
			tlsCfg:     config.TLSConfig{Automation: testAutomationConfig()},
			hello:      clientHello("app.acme.int"),
			wantIssued: []string{"app.acme.int"},
		},
		{
			name:       "IP SNI is issued on demand",
			tlsCfg:     config.TLSConfig{Certificates: files, Automation: testAutomationConfig()},
			hello:      clientHello("10.0.0.5"),
			wantIssued: []string{"10.0.0.5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newTestManager(t, tt.tlsCfg).GetCertificate(tt.hello)
			require.NoError(t, err)

			if tt.wantCert != nil {
				assert.Equal(t, tt.wantCert, got.Certificate)

				return
			}

			assert.Equal(t, tt.wantIssued, leafNames(got))
		})
	}
}
