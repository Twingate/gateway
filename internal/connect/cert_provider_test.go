// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"context"
	"crypto/tls"
	"net"
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

type recordingCertProvider struct {
	host       string
	aliases    []string
	shouldFail bool
	err        error
}

func (p *recordingCertProvider) Run(_ context.Context) {}

func (p *recordingCertProvider) GetCertificateForHost(_ context.Context, host string, aliases ...string) (*tls.Certificate, error) {
	p.host = host
	p.aliases = aliases

	if p.shouldFail {
		return nil, p.err
	}

	return &tls.Certificate{}, nil
}

func TestGetCertificateForHello(t *testing.T) {
	tests := []struct {
		name     string
		hello    *tls.ClientHelloInfo
		wantHost string
		wantErr  string
	}{
		{
			name:     "SNI host",
			hello:    &tls.ClientHelloInfo{ServerName: "app.internal"},
			wantHost: "app.internal",
		},
		{
			name:     "no SNI falls back to local IP",
			hello:    &tls.ClientHelloInfo{Conn: fakeAddrConn{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443}}},
			wantHost: "127.0.0.1",
		},
		{
			name:    "unparsable local address",
			hello:   &tls.ClientHelloInfo{Conn: fakeAddrConn{addr: &net.UnixAddr{Name: "/tmp/gateway.sock", Net: "unix"}}},
			wantErr: "failed to parse local address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &recordingCertProvider{}

			_, err := getCertificateForHello(provider, tt.hello)

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantHost, provider.host)
		})
	}
}

func TestNewCertProviderFromConfig(t *testing.T) {
	tests := []struct {
		name        string
		tlsCfg      config.TLSConfig
		wantType    any
		wantErr     error
		errContains string
	}{
		{
			name:     "static",
			tlsCfg:   config.TLSConfig{Static: &config.TLSStaticConfig{CertificateFile: "../../test/data/proxy/tls.crt", PrivateKeyFile: "../../test/data/proxy/tls.key"}},
			wantType: &CertReloader{},
		},
		{
			name: "dynamic",
			tlsCfg: config.TLSConfig{Dynamic: &config.TLSDynamicConfig{
				CA: config.TLSDynamicCAConfig{
					SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/proxy/tls.crt", PrivateKeyFile: "../../test/data/proxy/tls.key"},
				},
			}},
			wantType: &DynamicCert{},
		},
		{
			name: "dynamic with missing CA files",
			tlsCfg: config.TLSConfig{Dynamic: &config.TLSDynamicConfig{
				CA: config.TLSDynamicCAConfig{
					SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "missing.crt", PrivateKeyFile: "missing.key"},
				},
			}},
			errContains: "failed to create dynamic cert",
		},
		{
			name: "dynamic with vault CA",
			tlsCfg: config.TLSConfig{Dynamic: &config.TLSDynamicConfig{
				CA: config.TLSDynamicCAConfig{
					Vault: &config.TLSVaultCAConfig{
						VaultConfig: config.VaultConfig{Address: "https://vault.example.com:8200"},
						Role:        "gateway",
					},
				},
			}},
			wantType: &DynamicCert{},
		},
		{
			name: "dynamic with vault CA bundle missing",
			tlsCfg: config.TLSConfig{Dynamic: &config.TLSDynamicConfig{
				CA: config.TLSDynamicCAConfig{
					Vault: &config.TLSVaultCAConfig{
						VaultConfig: config.VaultConfig{Address: "https://vault.example.com:8200", CABundleFile: "missing.crt"},
						Role:        "gateway",
					},
				},
			}},
			errContains: "failed to create dynamic cert",
		},
		{
			name:    "neither static nor dynamic",
			wantErr: config.ErrMissingTLSConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := newCertProviderFromConfig(tt.tlsCfg, zap.NewNop())

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)

				return
			}

			if tt.errContains != "" {
				assert.ErrorContains(t, err, tt.errContains)

				return
			}

			require.NoError(t, err)
			assert.IsType(t, tt.wantType, provider)

			provider.Run(t.Context())
		})
	}
}
