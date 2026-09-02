// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapphandler

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/config"
	"gateway/internal/metrics"
	"gateway/internal/webapphandler/template"
	"gateway/test/data"
)

func TestNewConfig(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string]string
		wantErr     error
		errContains string
	}{
		{
			name: "valid header templates",
			headers: map[string]string{
				"Authorization": "Bearer {{jwt}}",
			},
		},
		{
			name: "invalid template syntax",
			headers: map[string]string{
				"X-Invalid": "{{twingate.jwt}}",
			},
			wantErr: template.ErrInvalidTemplate,
		},
		{
			name: "unsupported key",
			headers: map[string]string{
				"X-Bad": "{{unknown}}",
			},
			wantErr: template.ErrUnsupportedKey,
		},
		{
			name:    "empty headers",
			headers: map[string]string{},
		},
		{
			name:    "nil headers",
			headers: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewConfig(tt.headers, nil, nil, zap.NewNop())

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, cfg)
		})
	}
}

func TestNewConfig_CAPoolAddsCustomCA(t *testing.T) {
	cfg, err := NewConfig(nil, []config.CA{{Name: "custom", CertFile: "../../test/data/proxy/tls.crt"}}, metrics.RegisterRoundTripperMetrics(prometheus.NewRegistry()), zap.NewNop())
	require.NoError(t, err)

	block, _ := pem.Decode(data.ProxyCert)
	require.NotNil(t, block)

	caCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	_, err = caCert.Verify(x509.VerifyOptions{Roots: cfg.caPool})
	assert.NoError(t, err, "custom CA must be added to the pool")
}

func TestNewConfig_CAPool(t *testing.T) {
	invalidPEMFile := filepath.Join(t.TempDir(), "invalid.crt")
	require.NoError(t, os.WriteFile(invalidPEMFile, []byte("not a pem"), 0600))

	tests := []struct {
		name        string
		cas         []config.CA
		wantErr     bool
		errContains string
	}{
		{
			name:    "no CAs yields the system pool",
			cas:     nil,
			wantErr: false,
		},
		{
			name:        "missing CA file",
			cas:         []config.CA{{Name: "missing", CertFile: filepath.Join(t.TempDir(), "nope.crt")}},
			wantErr:     true,
			errContains: "\"missing\"",
		},
		{
			name:        "invalid PEM",
			cas:         []config.CA{{Name: "invalid", CertFile: invalidPEMFile}},
			wantErr:     true,
			errContains: "\"invalid\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewConfig(nil, tt.cas, metrics.RegisterRoundTripperMetrics(prometheus.NewRegistry()), zap.NewNop())
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)

				return
			}

			require.NoError(t, err)
			assert.NotNil(t, cfg.caPool, "pool defaults to the system cert pool when no CAs are configured")
		})
	}
}
