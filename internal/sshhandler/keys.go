// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

var (
	errUnsupportedKeyType = errors.New("unsupported key type")
	errUnsupportedKeySize = errors.New("unsupported key size")
)

type keyType string

const (
	keyTypeED25519 keyType = "ed25519"
	keyTypeECDSA   keyType = "ecdsa"
	keyTypeRSA     keyType = "rsa"
)

type keyConfig struct {
	typ  keyType
	bits int
}

func newKeyConfig(keyType string, keyBits int) (keyConfig, error) {
	switch keyType {
	// Ed25519 (also the default when no type is set)
	case "", "ed25519", ssh.KeyAlgoED25519:
		return keyConfig{typ: keyTypeED25519, bits: keyBits}, nil

	// ECDSA variants
	case "ecdsa":
		if keyBits == 0 {
			keyBits = 256
		}

		switch keyBits {
		case 256, 384, 521:
			return keyConfig{typ: keyTypeECDSA, bits: keyBits}, nil
		default:
			return keyConfig{}, fmt.Errorf("%w: ECDSA %d", errUnsupportedKeySize, keyBits)
		}
	case "ecdsa-sha2-nistp256":
		return keyConfig{typ: keyTypeECDSA, bits: 256}, nil
	case "ecdsa-sha2-nistp384":
		return keyConfig{typ: keyTypeECDSA, bits: 384}, nil
	case "ecdsa-sha2-nistp521":
		return keyConfig{typ: keyTypeECDSA, bits: 521}, nil

	// RSA variants
	case "rsa", "ssh-rsa":
		if keyBits == 0 {
			keyBits = 4096
		}

		switch keyBits {
		case 2048, 3072, 4096:
			return keyConfig{typ: keyTypeRSA, bits: keyBits}, nil
		default:
			return keyConfig{}, fmt.Errorf("%w: RSA %d", errUnsupportedKeySize, keyBits)
		}

	default:
		return keyConfig{}, fmt.Errorf("%w: %s", errUnsupportedKeyType, keyType)
	}
}

func (kc keyConfig) Generate(rand io.Reader) (ssh.Signer, ssh.PublicKey, error) {
	switch kc.typ {
	case keyTypeED25519, "":
		_, privateKey, err := ed25519.GenerateKey(rand)
		if err != nil {
			return nil, nil, err
		}

		return cryptoKeysToSSH(privateKey)
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
			return nil, nil, fmt.Errorf("%w: ecdsa %d", errUnsupportedKeySize, kc.bits)
		}

		privateKey, err := ecdsa.GenerateKey(curve, rand)
		if err != nil {
			return nil, nil, err
		}

		return cryptoKeysToSSH(privateKey)
	case keyTypeRSA:
		privateKey, err := rsa.GenerateKey(rand, kc.bits)
		if err != nil {
			return nil, nil, err
		}

		return cryptoKeysToSSH(privateKey)
	default:
		return nil, nil, fmt.Errorf("%w: %s", errUnsupportedKeyType, kc.typ)
	}
}

func cryptoKeysToSSH(privateKey crypto.PrivateKey) (ssh.Signer, ssh.PublicKey, error) {
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	return signer, signer.PublicKey(), nil
}
