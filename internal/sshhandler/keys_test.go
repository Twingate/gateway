// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestNewKeyConfig(t *testing.T) {
	tests := []struct {
		name       string
		keyType    string
		keyBits    int
		expectType keyType
		expectBits int
	}{
		{
			name:       "empty defaults to ed25519",
			keyType:    "",
			keyBits:    0,
			expectType: keyTypeED25519,
		},
		{
			name:       "ed25519",
			keyType:    "ed25519",
			keyBits:    0,
			expectType: keyTypeED25519,
		},
		{
			name:       "ssh-ed25519 (SSH key type)",
			keyType:    ssh.KeyAlgoED25519,
			keyBits:    0,
			expectType: keyTypeED25519,
		},
		{
			name:       "ecdsa default bits",
			keyType:    "ecdsa",
			keyBits:    0,
			expectType: keyTypeECDSA,
			expectBits: 256,
		},
		{
			name:       "ecdsa 384 bits",
			keyType:    "ecdsa",
			keyBits:    384,
			expectType: keyTypeECDSA,
			expectBits: 384,
		},
		{
			name:       "ecdsa 521 bits",
			keyType:    "ecdsa",
			keyBits:    521,
			expectType: keyTypeECDSA,
			expectBits: 521,
		},
		{
			name:       "ecdsa-sha2-nistp256 (SSH key type)",
			keyType:    ssh.KeyAlgoECDSA256,
			keyBits:    0,
			expectType: keyTypeECDSA,
			expectBits: 256,
		},
		{
			name:       "ecdsa-sha2-nistp384 (SSH key type)",
			keyType:    ssh.KeyAlgoECDSA384,
			keyBits:    0,
			expectType: keyTypeECDSA,
			expectBits: 384,
		},
		{
			name:       "ecdsa-sha2-nistp521 (SSH key type)",
			keyType:    ssh.KeyAlgoECDSA521,
			keyBits:    0,
			expectType: keyTypeECDSA,
			expectBits: 521,
		},
		{
			name:       "rsa default bits",
			keyType:    "rsa",
			keyBits:    0,
			expectType: keyTypeRSA,
			expectBits: 4096,
		},
		{
			name:       "ssh-rsa (SSH key type)",
			keyType:    ssh.KeyAlgoRSA,
			keyBits:    0,
			expectType: keyTypeRSA,
			expectBits: 4096,
		},
		{
			name:       "rsa 2048",
			keyType:    "rsa",
			keyBits:    2048,
			expectType: keyTypeRSA,
			expectBits: 2048,
		},
		{
			name:       "rsa 3072",
			keyType:    "rsa",
			keyBits:    3072,
			expectType: keyTypeRSA,
			expectBits: 3072,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc, err := newKeyConfig(tt.keyType, tt.keyBits)
			require.NoError(t, err)
			assert.Equal(t, tt.expectType, kc.typ)
			assert.Equal(t, tt.expectBits, kc.bits)
		})
	}
}

func TestNewKeyConfig_InvalidInputs(t *testing.T) {
	tests := []struct {
		name       string
		keyType    string
		keyBits    int
		wantErr    error
		wantErrMsg string
	}{
		{name: "unsupported key type", keyType: "nope", keyBits: 0, wantErr: errUnsupportedKeyType, wantErrMsg: "unsupported key type: nope"},
		{name: "ECDSA invalid bits", keyType: "ecdsa", keyBits: 123, wantErr: errUnsupportedKeySize, wantErrMsg: "unsupported key size: ECDSA 123"},
		{name: "RSA insecure bits", keyType: "rsa", keyBits: 1024, wantErr: errUnsupportedKeySize, wantErrMsg: "unsupported key size: RSA 1024"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newKeyConfig(tt.keyType, tt.keyBits)
			require.ErrorIs(t, err, tt.wantErr)
			require.EqualError(t, err, tt.wantErrMsg)
		})
	}
}

func TestKeyConfigGenerate(t *testing.T) {
	tests := []struct {
		name       string
		keyConfig  keyConfig
		expectAlgo string
	}{
		{
			name:       "ed25519",
			keyConfig:  keyConfig{typ: keyTypeED25519},
			expectAlgo: ssh.KeyAlgoED25519,
		},
		{
			name:       "ecdsa 256 bits",
			keyConfig:  keyConfig{typ: keyTypeECDSA, bits: 256},
			expectAlgo: ssh.KeyAlgoECDSA256,
		},
		{
			name:       "ecdsa 384 bits",
			keyConfig:  keyConfig{typ: keyTypeECDSA, bits: 384},
			expectAlgo: ssh.KeyAlgoECDSA384,
		},
		{
			name:       "ecdsa 521 bits",
			keyConfig:  keyConfig{typ: keyTypeECDSA, bits: 521},
			expectAlgo: ssh.KeyAlgoECDSA521,
		},
		{
			name:       "rsa 2048 bits",
			keyConfig:  keyConfig{typ: keyTypeRSA, bits: 2048},
			expectAlgo: ssh.KeyAlgoRSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, pub, err := tt.keyConfig.Generate(rand.Reader)
			require.NoError(t, err)
			require.NotNil(t, signer)
			require.NotNil(t, pub)

			assert.Equal(t, tt.expectAlgo, signer.PublicKey().Type())
			assert.Equal(t, tt.expectAlgo, pub.Type())
			assert.Equal(t, signer.PublicKey().Marshal(), pub.Marshal())
		})
	}
}

func TestKeyConfigGenerate_InvalidInputs(t *testing.T) {
	tests := []struct {
		name       string
		keyConfig  keyConfig
		wantErr    error
		wantErrMsg string
	}{
		{name: "unsupported key type", keyConfig: keyConfig{typ: "foo"}, wantErr: errUnsupportedKeyType, wantErrMsg: "unsupported key type: foo"},
		{name: "ECDSA invalid bits", keyConfig: keyConfig{typ: keyTypeECDSA, bits: 123}, wantErr: errUnsupportedKeySize, wantErrMsg: "unsupported key size: ecdsa 123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, pub, err := tt.keyConfig.Generate(rand.Reader)
			require.ErrorIs(t, err, tt.wantErr)
			require.EqualError(t, err, tt.wantErrMsg)
			assert.Nil(t, signer)
			assert.Nil(t, pub)
		})
	}
}
