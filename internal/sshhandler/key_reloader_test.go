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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

func TestKeyReloaderReloadWhenFileChanged(t *testing.T) {
	oldKeyPEM, oldPublicKey := generateCAKey(t)
	keyFile := createCAKeyFile(t, oldKeyPEM)
	keyReloader := newKeyReloader(keyFile, zap.NewNop())
	keyReloader.Run(t.Context())

	requireKeyReloaderSigner(t, keyReloader, oldPublicKey)

	newKeyPEM, newPublicKey := generateCAKey(t)
	replaceCAKeyFile(t, keyFile, newKeyPEM)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		signer := keyReloader.getSigner()
		require.NotNil(c, signer)

		assert.Equal(c, newPublicKey.Marshal(), signer.PublicKey().Marshal())
	}, time.Second, 5*time.Millisecond)
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

func requireKeyReloaderSigner(t *testing.T, keyReloader *keyReloader, expectedPublicKey ssh.PublicKey) {
	t.Helper()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		signer := keyReloader.getSigner()
		require.NotNil(c, signer)

		require.Equal(c, expectedPublicKey.Marshal(), signer.PublicKey().Marshal())
	}, time.Second, 5*time.Millisecond, "failed to get signer")
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
