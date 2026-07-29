// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/config"
)

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
			tlsCfg:   config.TLSConfig{Static: &config.TLSStaticConfig{CertificateFile: "../../test/data/ca/tls.crt", PrivateKeyFile: "../../test/data/ca/tls.key"}},
			wantType: &CertReloader{},
		},
		{
			name: "dynamic",
			tlsCfg: config.TLSConfig{Dynamic: &config.TLSDynamicConfig{
				CA: config.TLSDynamicCAConfig{
					SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/ca/tls.crt", PrivateKeyFile: "../../test/data/ca/tls.key"},
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
