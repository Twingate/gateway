// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/logging"
)

func TestNewConfig_Error(t *testing.T) {
	invalidPEMFile := filepath.Join(t.TempDir(), "invalid.crt")
	require.NoError(t, os.WriteFile(invalidPEMFile, []byte("not a pem"), 0o600))

	_, err := NewConfig(&gatewayconfig.PostgreSQLConfig{}, []gatewayconfig.UpstreamTrustedCABundle{{File: invalidPEMFile}}, logging.NewNop())

	assert.ErrorContains(t, err, "invalid.crt")
}
