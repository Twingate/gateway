// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewProxy_Success(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	viper.Set("config", "../test/data/config.yaml")

	p, err := newProxy(zap.NewNop())
	require.NoError(t, err)

	assert.NotNil(t, p)
}

func TestNewProxy_InvalidConfigPath(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	viper.Set("config", "/nonexistent/config.yaml")

	gateway, err := newProxy(zap.NewNop())
	require.Error(t, err)

	assert.Nil(t, gateway)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestNewProxy_InvalidConfigContent(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	content := `
twingate:
  network: acme
  host: test
`
	invalidConfig := filepath.Join(t.TempDir(), "invalid.yaml")
	err := os.WriteFile(invalidConfig, []byte(content), 0600)
	require.NoError(t, err)

	viper.Set("config", invalidConfig)

	gateway, err := newProxy(zap.NewNop())
	require.Error(t, err)

	assert.Nil(t, gateway)
	assert.Contains(t, err.Error(), "failed to validate config")
}
