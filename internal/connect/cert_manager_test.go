// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"crypto/tls"
	"net"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/config"
)

type fakeAddrConn struct {
	net.Conn

	addr net.Addr
}

func (c fakeAddrConn) LocalAddr() net.Addr { return c.addr }

func testAutomationConfig() *config.TLSAutomationConfig {
	return &config.TLSAutomationConfig{
		Issuer: config.TLSIssuerConfig{
			Local: &config.TLSLocalIssuerConfig{
				CertificateFile: "../../test/data/proxy/tls.crt",
				PrivateKeyFile:  "../../test/data/proxy/tls.key",
			},
		},
	}
}

func newTestCertManager(t *testing.T, tlsCfg config.TLSConfig) *CertManager {
	t.Helper()

	service, err := newCertManager(tlsCfg, zap.NewNop())
	require.NoError(t, err)

	// Load synchronously instead of waiting on the reloaders.
	for _, file := range tlsCfg.Certificates.Files {
		require.NoError(t, service.certs.load(file))
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

func TestNewCertManager_AutomationError(t *testing.T) {
	_, err := newCertManager(config.TLSConfig{
		Automation: &config.TLSAutomationConfig{
			Issuer: config.TLSIssuerConfig{
				Local: &config.TLSLocalIssuerConfig{CertificateFile: "missing.crt", PrivateKeyFile: "missing.key"},
			},
		},
	}, zap.NewNop())

	assert.ErrorContains(t, err, "failed to create cert automation")
}

func TestCertManager_GetCertificate(t *testing.T) {
	fooCert := generateCert(t, "foo.acme.int")
	files := config.TLSCertificateSources{Files: []config.TLSCertificateFileKeyPair{createKeyPair(t, fooCert)}}

	tests := []struct {
		name       string
		tlsCfg     config.TLSConfig
		hello      *tls.ClientHelloInfo
		wantCert   [][]byte
		wantIssued []string
		wantErr    string
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
			name:       "no SNI without configured certificates is issued for the local IP",
			tlsCfg:     config.TLSConfig{Automation: testAutomationConfig()},
			hello:      clientHello(""),
			wantIssued: []string{"127.0.0.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.hello.Conn = fakeAddrConn{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443}}
			got, err := newTestCertManager(t, tt.tlsCfg).GetCertificate(tt.hello)

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)

			if tt.wantCert != nil {
				assert.Equal(t, tt.wantCert, got.Certificate)

				return
			}

			assert.Equal(t, tt.wantIssued, leafNames(got))
		})
	}
}

func TestCertManager_GetCertificate_UnparsableLocalAddress(t *testing.T) {
	hello := clientHello("")
	hello.Conn = fakeAddrConn{addr: &net.UnixAddr{Name: "/tmp/gateway.sock", Net: "unix"}}

	_, err := newTestCertManager(t, config.TLSConfig{Automation: testAutomationConfig()}).GetCertificate(hello)

	assert.ErrorContains(t, err, "failed to parse local address")
}

func TestCertManager_GetCertificateForHost(t *testing.T) {
	fooCert := generateCert(t, "foo.acme.int")
	files := config.TLSCertificateSources{Files: []config.TLSCertificateFileKeyPair{createKeyPair(t, fooCert)}}

	tests := []struct {
		name       string
		tlsCfg     config.TLSConfig
		hello      *tls.ClientHelloInfo
		host       string
		aliases    []string
		wantCert   [][]byte
		wantIssued []string
	}{
		{
			name:     "host covered by a configured certificate",
			tlsCfg:   config.TLSConfig{Certificates: files, Automation: testAutomationConfig()},
			hello:    clientHello("foo.acme.int"),
			host:     "foo.acme.int",
			wantCert: fooCert.Certificate,
		},
		{
			name:       "uncovered host is issued on demand with its aliases",
			tlsCfg:     config.TLSConfig{Certificates: files, Automation: testAutomationConfig()},
			hello:      clientHello("app.acme.int"),
			host:       "app.acme.int",
			aliases:    []string{"alt.acme.int"},
			wantIssued: []string{"app.acme.int", "alt.acme.int"},
		},
		{
			name:       "IP host is issued on demand",
			tlsCfg:     config.TLSConfig{Certificates: files, Automation: testAutomationConfig()},
			hello:      clientHello("10.0.0.5"),
			host:       "10.0.0.5",
			wantIssued: []string{"10.0.0.5"},
		},
		{
			name:     "uncovered host without automation falls back to a configured certificate",
			tlsCfg:   config.TLSConfig{Certificates: files},
			hello:    clientHello("app.acme.int"),
			host:     "app.acme.int",
			wantCert: fooCert.Certificate,
		},
		{
			name:     "empty SNI falls back to a configured certificate",
			tlsCfg:   config.TLSConfig{Certificates: files},
			hello:    clientHello(""),
			host:     "app.acme.int",
			wantCert: fooCert.Certificate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := newTestCertManager(t, tt.tlsCfg)

			got, err := service.GetCertificateForHost(tt.hello, tt.host, tt.aliases...)
			require.NoError(t, err)

			if tt.wantCert != nil {
				assert.Equal(t, tt.wantCert, got.Certificate)

				return
			}

			assert.Equal(t, tt.wantIssued, leafNames(got))
		})
	}
}
