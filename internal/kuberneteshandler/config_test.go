// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package kuberneteshandler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/config"
)

func TestNewConfig(t *testing.T) {
	auditLogConfig := &config.AuditLogConfig{
		FlushInterval:      60,
		FlushSizeThreshold: 1000,
	}

	t.Run("Success with external upstream credentials", func(t *testing.T) {
		k8sConfig := &config.KubernetesConfig{
			Upstreams: []config.KubernetesUpstream{
				{
					Name:        "test-upstream",
					BearerToken: "test-token",
					CAFile:      "/path/to/ca.crt",
				},
			},
		}

		cfg, err := NewConfig(auditLogConfig, k8sConfig, nil, zap.NewNop())

		require.NoError(t, err)
		assert.Equal(t, "test-token", cfg.bearerToken)
		assert.Empty(t, cfg.bearerTokenFile)
		assert.Equal(t, "/path/to/ca.crt", cfg.caFile)
	})

	t.Run("Error when in-cluster discovery fails (no upstreams)", func(t *testing.T) {
		t.Setenv("KUBERNETES_SERVICE_HOST", "")

		k8sConfig := &config.KubernetesConfig{}

		cfg, err := NewConfig(auditLogConfig, k8sConfig, nil, zap.NewNop())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to load in-cluster configuration")
		assert.Nil(t, cfg)
	})
}
