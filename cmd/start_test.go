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

	"gateway/internal/logging"
)

func TestNewProxy_Success(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	viper.Set("config", "../test/data/config.yaml")

	cfg, err := loadConfig()
	require.NoError(t, err)

	p, err := newProxy(cfg, logging.NewNop())
	require.NoError(t, err)

	assert.NotNil(t, p)
}

func TestLoadConfig_InvalidConfigPath(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	viper.Set("config", "/nonexistent/config.yaml")

	cfg, err := loadConfig()
	require.Error(t, err)

	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestLoadConfig_InvalidConfigContent(t *testing.T) {
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

	cfg, err := loadConfig()
	require.Error(t, err)

	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to validate config")
}
