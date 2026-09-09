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

func TestManager_Run_IssuerFailsToStart(t *testing.T) {
	issuer := newStubIssuer()
	issuer.runErr = errStubRun

	manager := &Manager{certs: newReloader(nil, zap.NewNop()), automation: newStubAutomation(t, issuer)}

	require.ErrorIs(t, manager.Run(t.Context()), errStubRun)
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

func TestManager_GetCertificate_NoCertificates(t *testing.T) {
	got, err := newTestManager(t, config.TLSConfig{}).GetCertificate(clientHello("app.acme.int"))

	assert.Nil(t, got)
	require.ErrorIs(t, err, ErrNoCertificates)
}
