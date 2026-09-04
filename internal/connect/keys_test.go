// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyConfig(t *testing.T) {
	tests := []struct {
		name       string
		keyType    string
		keyBits    int
		expectType keyType
		expectBits int
		wantErr    error
	}{
		{
			name:       "empty defaults to ecdsa 256",
			expectType: keyTypeECDSA,
			expectBits: 256,
		},
		{
			name:       "ecdsa default bits",
			keyType:    "ecdsa",
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
			name:       "rsa default bits",
			keyType:    "rsa",
			expectType: keyTypeRSA,
			expectBits: 2048,
		},
		{
			name:       "rsa 4096 bits",
			keyType:    "rsa",
			keyBits:    4096,
			expectType: keyTypeRSA,
			expectBits: 4096,
		},
		{
			name:    "unsupported ecdsa bits",
			keyType: "ecdsa",
			keyBits: 123,
			wantErr: errUnsupportedKeyBits,
		},
		{
			name:    "unsupported rsa bits",
			keyType: "rsa",
			keyBits: 123,
			wantErr: errUnsupportedKeyBits,
		},
		{
			name:    "unsupported key type",
			keyType: "unknown",
			wantErr: errUnsupportedKeyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc, err := newKeyConfig(tt.keyType, tt.keyBits)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectType, kc.typ)
			assert.Equal(t, tt.expectBits, kc.bits)
		})
	}
}

func TestKeyConfig_generate(t *testing.T) {
	tests := []struct {
		name      string
		key       keyConfig
		wantCurve elliptic.Curve
		wantBits  int
		wantErr   error
	}{
		{name: "ecdsa 256", key: keyConfig{typ: keyTypeECDSA, bits: 256}, wantCurve: elliptic.P256()},
		{name: "ecdsa 384", key: keyConfig{typ: keyTypeECDSA, bits: 384}, wantCurve: elliptic.P384()},
		{name: "ecdsa 521", key: keyConfig{typ: keyTypeECDSA, bits: 521}, wantCurve: elliptic.P521()},
		{name: "rsa 2048", key: keyConfig{typ: keyTypeRSA, bits: 2048}, wantBits: 2048},
		{name: "unsupported ecdsa bits", key: keyConfig{typ: keyTypeECDSA, bits: 128}, wantErr: errUnsupportedKeyBits},
		{name: "unsupported key type", key: keyConfig{typ: "ed25519"}, wantErr: errUnsupportedKeyType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.key.generate()

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)

			if tt.key.typ == keyTypeRSA {
				rsaKey, ok := key.(*rsa.PrivateKey)
				require.True(t, ok, "expected an RSA key")
				assert.Equal(t, tt.wantBits, rsaKey.N.BitLen())

				return
			}

			ecdsaKey, ok := key.(*ecdsa.PrivateKey)
			require.True(t, ok, "expected an ECDSA key")
			assert.Equal(t, tt.wantCurve, ecdsaKey.Curve)
		})
	}
}
