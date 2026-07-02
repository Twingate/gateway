// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/ssh"

	gatewayconfig "gateway/internal/config"
	"gateway/test/data"
)

func TestEmbeddedCA_PublicKey(t *testing.T) {
	signer, pubKey, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	ca := &embeddedCA{
		signer: signer,
	}

	got, err := ca.publicKey(context.Background())
	require.NoError(t, err)
	require.Equal(t, pubKey.Marshal(), got.Marshal())
}

func TestEmbeddedCA_Sign(t *testing.T) {
	caSigner, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	ca := &embeddedCA{
		signer: caSigner,
	}

	publicKey, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	tests := []struct {
		name     string
		certType certType
	}{
		{name: "host cert", certType: HostCert},
		{name: "user cert", certType: UserCert},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &certificateRequest{
				certType:   tt.certType,
				publicKey:  publicKey,
				principals: []string{"test-principal"},
				ttl:        1 * time.Hour,
				permissions: ssh.Permissions{
					Extensions: map[string]string{"permit-pty": ""},
				},
			}

			cert, err := ca.sign(context.Background(), req)
			require.NoError(t, err)

			require.Equal(t, uint32(tt.certType), cert.CertType)
			require.Equal(t, publicKey.Marshal(), cert.Key.Marshal())
			require.Equal(t, []string{"test-principal"}, cert.ValidPrincipals)
			require.Equal(t, "twingate-14190c5d6ad4cbfa2e58069d25e06435f54c880654becf86735e9a77f49dc92b", cert.KeyId)
			require.Equal(t, map[string]string{"permit-pty": ""}, cert.Extensions)

			now := time.Now()
			require.LessOrEqual(t, cert.ValidAfter, mustUint64(now))
			require.Greater(t, cert.ValidBefore, mustUint64(now))
		})
	}
}

func TestNewManualCA_Success(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	caConfig, err := newManualCA("../../test/data/ssh/ca/ca", logger)
	require.NoError(t, err)

	require.NotNil(t, caConfig.GatewayHostCA)
	require.NotNil(t, caConfig.GatewayUserCA)
	require.Nil(t, caConfig.UpstreamHostCA, "UpstreamHostCA should be nil for TOFU mode")

	require.Same(t, caConfig.GatewayHostCA, caConfig.GatewayUserCA, "GatewayHostCA and GatewayUserCA should be the same instance")

	expectedPubKey, err := parsePublicKey(data.SSHCAPublicKey)
	require.NoError(t, err)

	pubKey, err := caConfig.GatewayHostCA.publicKey(context.Background())
	require.NoError(t, err)
	require.Equal(t, expectedPubKey.Marshal(), pubKey.Marshal())

	allLogs := logs.All()
	require.Len(t, allLogs, 1, "Expected exactly one log message")

	log := allLogs[0]
	require.Equal(t, "Using manual CA for SSH authentication", log.Message)
	require.Equal(t, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey))), log.ContextMap()["ca_public_key"])
}

func TestNewManualCA_PrivateKeyFileNotFound(t *testing.T) {
	_, err := newManualCA("/nonexistent/ca", zap.NewNop())
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read private key file")
}

func TestNewCAFromConfig_NilConfig(t *testing.T) {
	_, err := newCAFromConfig(nil, zap.NewNop())
	require.ErrorIs(t, err, gatewayconfig.ErrMissingCAConfig)
}

func TestNewCAFromConfig_EmptyConfig(t *testing.T) {
	config := &gatewayconfig.SSHCAConfig{}

	_, err := newCAFromConfig(config, zap.NewNop())
	require.ErrorIs(t, err, gatewayconfig.ErrMissingCAConfig)
}

func TestNewCAFromConfig_ManualConfig(t *testing.T) {
	config := &gatewayconfig.SSHCAConfig{
		Manual: &gatewayconfig.SSHCAManualConfig{
			PrivateKeyFile: "../../test/data/ssh/ca/ca",
		},
	}

	caConfig, err := newCAFromConfig(config, zap.NewNop())
	require.NoError(t, err)

	require.IsType(t, &embeddedCA{}, caConfig.GatewayHostCA)
	require.IsType(t, &embeddedCA{}, caConfig.GatewayUserCA)
	require.Nil(t, caConfig.UpstreamHostCA)
}

func TestUpstreamHostKeyCallback_NilUpstreamHostCA(t *testing.T) {
	upstreamAddress := "10.0.0.1:22"
	caConfig := &caConfig{
		UpstreamHostCA: nil,
	}

	callback, err := caConfig.upstreamHostKeyCallback(context.Background(), upstreamAddress)
	require.NoError(t, err)
	require.NotNil(t, callback)

	publicKey, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	// TOFU verification with public key
	err = callback(upstreamAddress, nil, publicKey)
	require.NoError(t, err)
}

func TestUpstreamHostKeyCallback_WithUpstreamHostCA(t *testing.T) {
	upstreamAddress := "10.0.0.1:22"
	caSigner, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	upstreamCA := &embeddedCA{
		signer: caSigner,
	}

	caConfig := &caConfig{
		UpstreamHostCA: upstreamCA,
	}

	callback, err := caConfig.upstreamHostKeyCallback(context.Background(), upstreamAddress)
	require.NoError(t, err)
	require.NotNil(t, callback)

	hostSigner, hostPubKey, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	req := &certificateRequest{
		certType:  HostCert,
		publicKey: hostPubKey,
		ttl:       1 * time.Hour,
	}

	cert, err := upstreamCA.sign(context.Background(), req)
	require.NoError(t, err)

	certSigner, err := ssh.NewCertSigner(cert, hostSigner)
	require.NoError(t, err)

	err = callback(upstreamAddress, nil, certSigner.PublicKey())
	require.NoError(t, err)
}

func TestUpstreamHostKeyCallback_WithUpstreamHostCA_RejectsPublicKey(t *testing.T) {
	upstreamAddress := "10.0.0.1:22"
	caSigner, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	upstreamCA := &embeddedCA{
		signer: caSigner,
	}

	caConfig := &caConfig{
		UpstreamHostCA: upstreamCA,
	}

	callback, err := caConfig.upstreamHostKeyCallback(context.Background(), upstreamAddress)
	require.NoError(t, err)

	pubKey, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	err = callback(upstreamAddress, nil, pubKey)
	require.Error(t, err)
}

func TestMustUint64(t *testing.T) {
	tests := []struct {
		name   string
		input  time.Time
		expect uint64
	}{
		{name: "current time", input: time.Unix(1234567890, 0), expect: 1234567890},
		{name: "epoch", input: time.Unix(0, 0), expect: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mustUint64(tt.input)
			require.Equal(t, tt.expect, result)
		})
	}
}

func TestMustUint64_PanicsOnNegativeTime(t *testing.T) {
	require.Panics(t, func() {
		mustUint64(time.Unix(-1, 0))
	})
}
