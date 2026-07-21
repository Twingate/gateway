// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

func TestKeyReloader_load(t *testing.T) {
	keyPEM, publicKey := generateCAKey(t)
	keyFile := createCAKeyFile(t, keyPEM)
	invalidKeyFile := createCAKeyFile(t, []byte("not a private key"))

	tests := []struct {
		name    string
		keyFile string
		wantErr bool
	}{
		{name: "valid key", keyFile: keyFile},
		{name: "invalid key", keyFile: invalidKeyFile, wantErr: true},
		{name: "missing file", keyFile: "nonexistent", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kr := newKeyReloader(tt.keyFile, zap.NewNop())

			if tt.wantErr {
				require.Error(t, kr.load())

				return
			}

			require.NoError(t, kr.load())

			signer := kr.getSigner()
			require.NotNil(t, signer)
			assert.Equal(t, publicKey.Marshal(), signer.PublicKey().Marshal())
		})
	}
}

func TestKeyReloaderSignalsReloadOnKeyChange(t *testing.T) {
	keyPEM, _ := generateCAKey(t)
	keyFile := createCAKeyFile(t, keyPEM)
	keyReloader := newKeyReloader(keyFile, zap.NewNop())

	requireNoReloadSignal := func() {
		t.Helper()

		select {
		case <-keyReloader.reloadCh:
			t.Fatal("unexpected reload signal")
		default:
		}
	}

	// The initial load does not signal
	require.NoError(t, keyReloader.load())
	requireNoReloadSignal()

	// Reloading an unchanged key does not signal
	require.NoError(t, keyReloader.load())
	requireNoReloadSignal()

	// Signals coalesce: two changes before the pending signal is consumed produce one signal
	for range 2 {
		nextKeyPEM, _ := generateCAKey(t)
		replaceCAKeyFile(t, keyFile, nextKeyPEM)
		require.NoError(t, keyReloader.load())
	}

	select {
	case <-keyReloader.reloadCh:
	default:
		t.Fatal("expected reload signal after key changes")
	}

	requireNoReloadSignal()
}

func generateCAKey(t *testing.T) (keyPEM []byte, publicKey ssh.PublicKey) {
	t.Helper()

	rawPublicKey, rawPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemBlock, err := ssh.MarshalPrivateKey(rawPrivateKey, "")
	require.NoError(t, err)

	publicKey, err = ssh.NewPublicKey(rawPublicKey)
	require.NoError(t, err)

	return pem.EncodeToMemory(pemBlock), publicKey
}

func createCAKeyFile(t *testing.T, keyPEM []byte) string {
	t.Helper()

	keyFile := filepath.Join(t.TempDir(), "ca")
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0600))

	return keyFile
}

func replaceCAKeyFile(t *testing.T, keyFile string, keyPEM []byte) {
	t.Helper()

	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0600))
}
