// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestNewKeyConfigAndGenerate_ByKeyType(t *testing.T) {
	tests := []struct {
		name       string
		keyType    string
		keyBits    int
		expectType keyType
		expectBits int
		expectAlgo string
	}{
		{
			name:       "empty defaults to ed25519",
			keyType:    "",
			keyBits:    0,
			expectType: keyTypeED25519,
			expectAlgo: ssh.KeyAlgoED25519,
		},
		{
			name:       "ed25519",
			keyType:    "ed25519",
			keyBits:    0,
			expectType: keyTypeED25519,
			expectAlgo: ssh.KeyAlgoED25519,
		},
		{
			name:       "ssh-ed25519 (SSH key type)",
			keyType:    ssh.KeyAlgoED25519,
			keyBits:    0,
			expectType: keyTypeED25519,
			expectAlgo: ssh.KeyAlgoED25519,
		},
		{
			name:       "ecdsa default bits",
			keyType:    "ecdsa",
			keyBits:    0,
			expectType: keyTypeECDSA,
			expectBits: 256,
			expectAlgo: "ecdsa-sha2-nistp256",
		},
		{
			name:       "ecdsa 384 bits",
			keyType:    "ecdsa",
			keyBits:    384,
			expectType: keyTypeECDSA,
			expectBits: 384,
			expectAlgo: "ecdsa-sha2-nistp384",
		},
		{
			name:       "ecdsa 521 bits",
			keyType:    "ecdsa",
			keyBits:    521,
			expectType: keyTypeECDSA,
			expectBits: 521,
			expectAlgo: "ecdsa-sha2-nistp521",
		},
		{
			name:       "ecdsa-sha2-nistp256 (SSH key type)",
			keyType:    ssh.KeyAlgoECDSA256,
			keyBits:    0,
			expectType: keyTypeECDSA,
			expectBits: 256,
			expectAlgo: "ecdsa-sha2-nistp256",
		},
		{
			name:       "ecdsa-sha2-nistp384 (SSH key type)",
			keyType:    ssh.KeyAlgoECDSA384,
			keyBits:    0,
			expectType: keyTypeECDSA,
			expectBits: 384,
			expectAlgo: "ecdsa-sha2-nistp384",
		},
		{
			name:       "ecdsa-sha2-nistp521 (SSH key type)",
			keyType:    ssh.KeyAlgoECDSA521,
			keyBits:    0,
			expectType: keyTypeECDSA,
			expectBits: 521,
			expectAlgo: "ecdsa-sha2-nistp521",
		},
		{
			name:       "rsa default bits",
			keyType:    "rsa",
			keyBits:    0,
			expectType: keyTypeRSA,
			expectBits: 4096,
			expectAlgo: "ssh-rsa",
		},
		{
			name:       "ssh-rsa (SSH key type)",
			keyType:    ssh.KeyAlgoRSA,
			keyBits:    0,
			expectType: keyTypeRSA,
			expectBits: 4096,
			expectAlgo: "ssh-rsa",
		},
		{
			name:       "rsa 2048",
			keyType:    "rsa",
			keyBits:    2048,
			expectType: keyTypeRSA,
			expectBits: 2048,
			expectAlgo: "ssh-rsa",
		},
		{
			name:       "rsa 3072",
			keyType:    "rsa",
			keyBits:    3072,
			expectType: keyTypeRSA,
			expectBits: 3072,
			expectAlgo: "ssh-rsa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc, err := newKeyConfig(tt.keyType, tt.keyBits)
			require.NoError(t, err)
			require.Equal(t, tt.expectType, kc.typ)
			require.Equal(t, tt.expectBits, kc.bits)

			signer, pub, err := kc.Generate(rand.Reader)
			require.NoError(t, err)
			require.NotNil(t, signer)
			require.NotNil(t, pub)

			require.Equal(t, tt.expectAlgo, signer.PublicKey().Type())
			require.Equal(t, tt.expectAlgo, pub.Type())
			require.Equal(t, signer.PublicKey().Marshal(), pub.Marshal())
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
