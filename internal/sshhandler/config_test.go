// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	gatewayconfig "gateway/internal/config"
	"gateway/test/data"
)

func TestNewConfig_Success(t *testing.T) {
	auditLog := &gatewayconfig.AuditLogConfig{
		FlushInterval:      time.Minute * 5,
		FlushSizeThreshold: 2000,
	}

	sshConfig := &gatewayconfig.SSHConfig{
		Gateway: gatewayconfig.SSHGatewayConfig{
			Username:        "gateway",
			Key:             gatewayconfig.SSHKeyConfig{Type: "ed25519"},
			HostCertificate: gatewayconfig.SSHCertificateConfig{TTL: 24 * time.Hour},
			UserCertificate: gatewayconfig.SSHCertificateConfig{TTL: 5 * time.Minute},
		},
		CA: gatewayconfig.SSHCAConfig{
			Manual: &gatewayconfig.SSHCAManualConfig{
				PrivateKeyFile: "../../test/data/ssh/ca/ca",
			},
		},
	}

	config, err := NewConfig(auditLog, sshConfig, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, config)

	assert.Equal(t, auditLog, config.auditLog)
	assert.Equal(t, "gateway", config.gatewayUsername)
}

func TestNewConfig_WithManualCA(t *testing.T) {
	auditLog := &gatewayconfig.AuditLogConfig{}

	sshConfig := &gatewayconfig.SSHConfig{
		Gateway: gatewayconfig.SSHGatewayConfig{
			Username:        "gateway",
			Key:             gatewayconfig.SSHKeyConfig{Type: "ed25519"},
			HostCertificate: gatewayconfig.SSHCertificateConfig{TTL: 24 * time.Hour},
			UserCertificate: gatewayconfig.SSHCertificateConfig{TTL: 5 * time.Minute},
		},
		CA: gatewayconfig.SSHCAConfig{
			Manual: &gatewayconfig.SSHCAManualConfig{
				PrivateKeyFile: "../../test/data/ssh/ca/ca",
			},
		},
	}

	config, err := NewConfig(auditLog, sshConfig, zap.NewNop())
	require.NoError(t, err)
	assert.NotNil(t, config)
}

func TestNewConfig_InvalidManualCA(t *testing.T) {
	auditLog := &gatewayconfig.AuditLogConfig{}

	sshConfig := &gatewayconfig.SSHConfig{
		Gateway: gatewayconfig.SSHGatewayConfig{
			Username:        "gateway",
			Key:             gatewayconfig.SSHKeyConfig{Type: "ed25519"},
			HostCertificate: gatewayconfig.SSHCertificateConfig{TTL: 24 * time.Hour},
			UserCertificate: gatewayconfig.SSHCertificateConfig{TTL: 5 * time.Minute},
		},
		CA: gatewayconfig.SSHCAConfig{
			Manual: &gatewayconfig.SSHCAManualConfig{
				PrivateKeyFile: "nonexistent.key",
			},
		},
	}

	config, err := NewConfig(auditLog, sshConfig, zap.NewNop())
	require.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "failed to create ca")
}

func TestKeysEqual_SameKey(t *testing.T) {
	key1, err := parsePublicKey(data.SSHCAPublicKey)
	require.NoError(t, err)

	key2, err := parsePublicKey(data.SSHCAPublicKey)
	require.NoError(t, err)

	assert.True(t, keysEqual(key1, key2))
}

func TestKeysEqual_DifferentKeys(t *testing.T) {
	key1, err := parsePublicKey(data.SSHCAPublicKey)
	require.NoError(t, err)

	key2, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	assert.False(t, keysEqual(key1, key2))
}

func TestKeysEqual_NilKeys(t *testing.T) {
	key, err := parsePublicKey(data.SSHCAPublicKey)
	require.NoError(t, err)

	// Test nil cases
	assert.False(t, keysEqual(nil, key))
	assert.False(t, keysEqual(key, nil))
	assert.False(t, keysEqual(nil, nil))
}

func TestTOFUHostKey_FirstConnection(t *testing.T) {
	address := "10.0.0.1:22"
	tofu := newTOFUHostKey(address)

	key, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	// First connection should succeed and store the key
	err = tofu.checkHostKey(address, nil, key)
	require.NoError(t, err)
	assert.True(t, keysEqual(tofu.knownKey, key))
}

func TestTOFUHostKey_SameKey(t *testing.T) {
	address := "10.0.0.1:22"

	key, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	tofu := newTOFUHostKey(address)
	err = tofu.checkHostKey(address, nil, key)
	require.NoError(t, err)

	// Connection with same key should succeed
	err = tofu.checkHostKey(address, nil, key)
	require.NoError(t, err)
}

func TestTOFUHostKey_DifferentKey(t *testing.T) {
	address := "10.0.0.1:22"

	key1, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	key2, err := parsePublicKey(data.SSHCAPublicKey)
	require.NoError(t, err)

	tofu := newTOFUHostKey(address)
	err = tofu.checkHostKey(address, nil, key1)
	require.NoError(t, err)

	// Connection with different key should fail
	err = tofu.checkHostKey(address, nil, key2)
	require.ErrorIs(t, err, errTOFUHostKeyMismatch)
}

func TestTOFUHostKey_AddressMismatch(t *testing.T) {
	tofu := newTOFUHostKey("10.0.0.1:22")

	key, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	// Connection from different address should fail
	err = tofu.checkHostKey("10.0.0.2:22", nil, key)
	require.ErrorIs(t, err, errTOFUAddressMismatch)
}
