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

func newTestManager(t *testing.T, tlsCfg config.TLSConfig, webAppCfg *config.WebAppConfig) *Manager {
	t.Helper()

	service, err := NewManager(tlsCfg, webAppCfg, zap.NewNop())
	require.NoError(t, err)

	// Load synchronously instead of waiting on the reloaders.
	if tlsCfg.Certificates != nil {
		for _, file := range tlsCfg.Certificates.Files {
			require.NoError(t, service.certs.load(file))
		}
	}

	if webAppCfg != nil && webAppCfg.TLS != nil {
		for _, file := range webAppCfg.TLS.Certificates.Files {
			_ = service.webAppCerts.load(file)
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
	}, nil, zap.NewNop())

	assert.ErrorContains(t, err, "failed to create cert automation")
}

func TestManager_Run_IssuerFailsToStart(t *testing.T) {
	issuer := newStubIssuer()
	issuer.runErr = errStubRun

	manager := &Manager{certs: newReloader(nil, zap.NewNop()), webAppCerts: newReloader(nil, zap.NewNop()), automation: newStubAutomation(t, issuer)}

	require.ErrorIs(t, manager.Run(t.Context()), errStubRun)
}

func TestManager_GetCertificate(t *testing.T) {
	automationCfg := &config.TLSAutomationConfig{
		Issuer: config.TLSIssuerConfig{
			Local: &config.TLSLocalIssuerConfig{
				CertificateFile: "../../../test/data/proxy/tls.crt",
				PrivateKeyFile:  "../../../test/data/proxy/tls.key",
			},
		},
	}

	fooCert := generateCert(t, "foo.acme.int")
	files := &config.TLSCertificateSources{Files: []config.TLSCertificateFileKeyPair{createKeyPair(t, fooCert)}}
	webAppCfg := &config.WebAppConfig{TLS: &config.WebAppTLSConfig{
		Certificates: config.TLSCertificateSources{Files: []config.TLSCertificateFileKeyPair{createKeyPair(t, generateCert(t, "*.acme.int"))}},
	}}

	tests := []struct {
		name       string
		tlsCfg     config.TLSConfig
		webAppCfg  *config.WebAppConfig
		hello      *tls.ClientHelloInfo
		wantCert   [][]byte
		wantIssued []string
	}{
		{
			name:     "SNI covered by a configured certificate",
			tlsCfg:   config.TLSConfig{Certificates: files, Automation: automationCfg},
			hello:    clientHello("foo.acme.int"),
			wantCert: fooCert.Certificate,
		},
		{
			name:       "uncovered SNI is issued on demand",
			tlsCfg:     config.TLSConfig{Certificates: files, Automation: automationCfg},
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
			tlsCfg:   config.TLSConfig{Certificates: files, Automation: automationCfg},
			hello:    clientHello(""),
			wantCert: fooCert.Certificate,
		},
		{
			name:      "SNI covered only by a Web App certificate is not served",
			tlsCfg:    config.TLSConfig{Certificates: files},
			webAppCfg: webAppCfg,
			hello:     clientHello("app.acme.int"),
			wantCert:  fooCert.Certificate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newTestManager(t, tt.tlsCfg, tt.webAppCfg).GetCertificate(tt.hello)
			require.NoError(t, err)

			if tt.wantCert != nil {
				assert.Equal(t, tt.wantCert, got.Certificate)

				return
			}

			assert.Equal(t, tt.wantIssued, leafNames(got))
		})
	}
}

func TestManager_GetWebAppCertificate(t *testing.T) {
	fooCert := generateCert(t, "foo.acme.int")
	tlsCfg := config.TLSConfig{Certificates: &config.TLSCertificateSources{Files: []config.TLSCertificateFileKeyPair{createKeyPair(t, fooCert)}}}

	webAppCert := generateCert(t, "*.acme.int")
	exactCert := generateCert(t, "app.acme.int")
	webAppKeyPair := createKeyPair(t, webAppCert)
	exactKeyPair := createKeyPair(t, exactCert)
	missing := config.TLSCertificateFileKeyPair{CertificateFile: "nonexistent.crt", PrivateKeyFile: "nonexistent.key"}

	tests := []struct {
		name     string
		files    []config.TLSCertificateFileKeyPair
		hello    *tls.ClientHelloInfo
		wantCert [][]byte
	}{
		{
			name:     "SNI covered by both sources is served the Web App certificate",
			files:    []config.TLSCertificateFileKeyPair{webAppKeyPair},
			hello:    clientHello("foo.acme.int"),
			wantCert: webAppCert.Certificate,
		},
		{
			name:     "first Web App certificate in configuration order wins",
			files:    []config.TLSCertificateFileKeyPair{webAppKeyPair, exactKeyPair},
			hello:    clientHello("app.acme.int"),
			wantCert: webAppCert.Certificate,
		},
		{
			name:     "SNI beyond the wildcard falls back to the TLS certificates",
			files:    []config.TLSCertificateFileKeyPair{webAppKeyPair},
			hello:    clientHello("app.other.acme.int"),
			wantCert: fooCert.Certificate,
		},
		{
			name:     "no SNI falls back to the TLS certificates",
			files:    []config.TLSCertificateFileKeyPair{webAppKeyPair},
			hello:    clientHello(""),
			wantCert: fooCert.Certificate,
		},
		{
			name:     "missing Web App files fall back to the TLS certificates",
			files:    []config.TLSCertificateFileKeyPair{missing},
			hello:    clientHello("app.acme.int"),
			wantCert: fooCert.Certificate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			webAppCfg := &config.WebAppConfig{TLS: &config.WebAppTLSConfig{Certificates: config.TLSCertificateSources{Files: tt.files}}}

			got, err := newTestManager(t, tlsCfg, webAppCfg).GetWebAppCertificate(tt.hello)
			require.NoError(t, err)

			assert.Equal(t, tt.wantCert, got.Certificate)
		})
	}
}

func TestManager_Run_ReloadsWebAppCertificates(t *testing.T) {
	webAppCert := generateCert(t, "app.acme.int")
	keyPair := createKeyPair(t, webAppCert)
	webAppCfg := &config.WebAppConfig{TLS: &config.WebAppTLSConfig{Certificates: config.TLSCertificateSources{Files: []config.TLSCertificateFileKeyPair{keyPair}}}}

	manager, err := NewManager(config.TLSConfig{}, webAppCfg, zap.NewNop())
	require.NoError(t, err)
	require.NoError(t, manager.Run(t.Context()))

	requireCert(t, manager.webAppCerts, "app.acme.int", webAppCert)

	newWebAppCert := generateCert(t, "app.acme.int")
	replaceKeyPair(t, keyPair, newWebAppCert)

	requireCert(t, manager.webAppCerts, "app.acme.int", newWebAppCert)
}

func TestManager_GetCertificate_NoCertificates(t *testing.T) {
	got, err := newTestManager(t, config.TLSConfig{}, nil).GetCertificate(clientHello("app.acme.int"))

	assert.Nil(t, got)
	require.ErrorIs(t, err, ErrNoCertificates)
}
