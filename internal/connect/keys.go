// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
)

var (
	errUnsupportedKeyType = errors.New("unsupported key type")
	errUnsupportedKeyBits = errors.New("unsupported key bits")
)

type keyType string

const (
	keyTypeECDSA keyType = "ecdsa"
	keyTypeRSA   keyType = "rsa"
)

type keyConfig struct {
	typ  keyType
	bits int
}

func newKeyConfig(keyType string, keyBits int) (keyConfig, error) {
	switch keyType {
	// ECDSA (also the default when no type is set)
	case "", "ecdsa":
		if keyBits == 0 {
			keyBits = 256
		}

		switch keyBits {
		case 256, 384, 521:
			return keyConfig{typ: keyTypeECDSA, bits: keyBits}, nil
		default:
			return keyConfig{}, fmt.Errorf("%w: ECDSA %d", errUnsupportedKeyBits, keyBits)
		}

	case "rsa":
		if keyBits == 0 {
			keyBits = 2048
		}

		switch keyBits {
		case 2048, 3072, 4096:
			return keyConfig{typ: keyTypeRSA, bits: keyBits}, nil
		default:
			return keyConfig{}, fmt.Errorf("%w: RSA %d", errUnsupportedKeyBits, keyBits)
		}

	default:
		return keyConfig{}, fmt.Errorf("%w: %s", errUnsupportedKeyType, keyType)
	}
}

func (kc keyConfig) generate() (crypto.Signer, error) {
	switch kc.typ {
	case keyTypeECDSA:
		var curve elliptic.Curve

		switch kc.bits {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("%w: ECDSA %d", errUnsupportedKeyBits, kc.bits)
		}

		return ecdsa.GenerateKey(curve, rand.Reader)
	case keyTypeRSA:
		return rsa.GenerateKey(rand.Reader, kc.bits)
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedKeyType, kc.typ)
	}
}
