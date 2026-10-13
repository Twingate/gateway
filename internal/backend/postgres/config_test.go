// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gateway/internal/config"
	"gateway/internal/logging"
)

func TestNewConfig(t *testing.T) {
	passwordFile := filepath.Join(t.TempDir(), "pg.pw")
	require.NoError(t, os.WriteFile(passwordFile, []byte("from-file\n"), 0600))

	cfg := &config.PostgreSQLConfig{
		Credentials: []config.PostgreSQLCredential{
			{Name: "prod-viewer", Password: "inline"},
			{Name: "prod-editor", PasswordFile: passwordFile},
		},
	}

	got, err := NewConfig(cfg, logging.NewNop())
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"prod-viewer": "inline",
		"prod-editor": "from-file",
	}, got.passwordsByCredential, "passwordFile trailing newline should be trimmed")
}

func TestNewConfig_PasswordFileMissing(t *testing.T) {
	cfg := &config.PostgreSQLConfig{
		Credentials: []config.PostgreSQLCredential{
			{Name: "prod-viewer", PasswordFile: "/does/not/exist"},
		},
	}

	_, err := NewConfig(cfg, logging.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "passwordFile")
}
