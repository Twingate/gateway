// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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

func TestKeyReloaderReloadWhenFileReplacedAtomically(t *testing.T) {
	oldKeyPEM, oldPublicKey := generateCAKey(t)
	keyFile := createCAKeyFile(t, oldKeyPEM)
	keyReloader := newKeyReloader(keyFile, zap.NewNop())
	keyReloader.Run(t.Context())

	requireKeyReloaderSigner(t, keyReloader, oldPublicKey)

	// Replace the file atomically via rename instead of writing in place
	newKeyPEM, newPublicKey := generateCAKey(t)
	tmpFile := filepath.Join(t.TempDir(), "ca.new")
	require.NoError(t, os.WriteFile(tmpFile, newKeyPEM, 0600))
	require.NoError(t, os.Rename(tmpFile, keyFile))

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		signer := keyReloader.getSigner()
		require.NotNil(c, signer)

		assert.Equal(c, newPublicKey.Marshal(), signer.PublicKey().Marshal())
	}, time.Second, 5*time.Millisecond)
}

// TestKeyReloaderReloadWhenKubernetesSecretUpdated simulates the kubelet AtomicWriter
// update sequence for a projected secret volume:
//
//	mount/ca -> ..data/ca, ..data -> ..timestamp1, update swaps ..data to ..timestamp2 and removes ..timestamp1
func TestKeyReloaderReloadWhenKubernetesSecretUpdated(t *testing.T) {
	mount := t.TempDir()

	oldKeyPEM, oldPublicKey := generateCAKey(t)
	oldDataDir := filepath.Join(mount, "..timestamp1")
	require.NoError(t, os.Mkdir(oldDataDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(oldDataDir, "ca"), oldKeyPEM, 0600))
	require.NoError(t, os.Symlink("..timestamp1", filepath.Join(mount, "..data")))
	require.NoError(t, os.Symlink(filepath.Join("..data", "ca"), filepath.Join(mount, "ca")))

	keyReloader := newKeyReloader(filepath.Join(mount, "ca"), zap.NewNop())
	keyReloader.Run(t.Context())

	requireKeyReloaderSigner(t, keyReloader, oldPublicKey)

	newKeyPEM, newPublicKey := generateCAKey(t)
	newDataDir := filepath.Join(mount, "..timestamp2")
	require.NoError(t, os.Mkdir(newDataDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(newDataDir, "ca"), newKeyPEM, 0600))
	require.NoError(t, os.Symlink("..timestamp2", filepath.Join(mount, "..data_tmp")))
	require.NoError(t, os.Rename(filepath.Join(mount, "..data_tmp"), filepath.Join(mount, "..data")))
	require.NoError(t, os.RemoveAll(oldDataDir))

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

	// Loading a changed key signals once
	newKeyPEM, _ := generateCAKey(t)
	replaceCAKeyFile(t, keyFile, newKeyPEM)
	require.NoError(t, keyReloader.load())

	select {
	case <-keyReloader.reloadCh:
	default:
		t.Fatal("expected reload signal after key change")
	}

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

func TestKeyReloaderRecoversAfterInvalidKey(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)

	oldKeyPEM, oldPublicKey := generateCAKey(t)
	keyFile := createCAKeyFile(t, oldKeyPEM)
	keyReloader := newKeyReloader(keyFile, zap.New(core))
	keyReloader.Run(t.Context())

	requireKeyReloaderSigner(t, keyReloader, oldPublicKey)

	// A bad rotation is logged and keeps the previous key
	replaceCAKeyFile(t, keyFile, []byte("not a private key"))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		require.NotEmpty(c, logs.FilterMessage("failed to load CA private key file").All())
	}, time.Second, 5*time.Millisecond, "failed load was not logged")

	signer := keyReloader.getSigner()
	require.NotNil(t, signer)
	assert.Equal(t, oldPublicKey.Marshal(), signer.PublicKey().Marshal())

	// The watcher keeps running and picks up the next good rotation
	newKeyPEM, newPublicKey := generateCAKey(t)
	replaceCAKeyFile(t, keyFile, newKeyPEM)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		signer := keyReloader.getSigner()
		require.NotNil(c, signer)

		assert.Equal(c, newPublicKey.Marshal(), signer.PublicKey().Marshal())
	}, time.Second, 5*time.Millisecond)
}

func TestKeyReloaderRetriesWatchWhenFileRemoved(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)

	keyPEM, publicKey := generateCAKey(t)
	keyFile := createCAKeyFile(t, keyPEM)
	keyReloader := newKeyReloader(keyFile, zap.New(core))
	keyReloader.Run(t.Context())

	requireKeyReloaderSigner(t, keyReloader, publicKey)

	require.NoError(t, os.Remove(keyFile))

	// Re-adding the watch fails because the file is gone: the watch exits and retries later
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		require.NotEmpty(c, logs.FilterMessage("failed to watch CA private key file, will retry later").All())
	}, time.Second, 5*time.Millisecond, "watch retry was not logged")

	// The last good key remains available
	signer := keyReloader.getSigner()
	require.NotNil(t, signer)
	assert.Equal(t, publicKey.Marshal(), signer.PublicKey().Marshal())
}

func TestKeyReloaderDontReloadWhenInvalidKey(t *testing.T) {
	oldKeyPEM, oldPublicKey := generateCAKey(t)
	keyFile := createCAKeyFile(t, oldKeyPEM)
	keyReloader := newKeyReloader(keyFile, zap.NewNop())
	require.NoError(t, keyReloader.load())

	replaceCAKeyFile(t, keyFile, []byte("not a private key"))
	require.Error(t, keyReloader.load())

	// The failed load does not signal a reload
	select {
	case <-keyReloader.reloadCh:
		t.Fatal("unexpected reload signal after loading an invalid key")
	default:
	}

	// Ensure signer is unchanged
	signer := keyReloader.getSigner()
	require.NotNil(t, signer)
	assert.Equal(t, oldPublicKey.Marshal(), signer.PublicKey().Marshal())
}

func TestKeyReloaderDontReloadWhenContextIsCanceled(t *testing.T) {
	oldKeyPEM, oldPublicKey := generateCAKey(t)
	keyFile := createCAKeyFile(t, oldKeyPEM)

	keyReloader := newKeyReloader(keyFile, zap.NewNop())

	ctx, cancel := context.WithCancel(t.Context())
	keyReloader.Run(ctx)

	requireKeyReloaderSigner(t, keyReloader, oldPublicKey)

	cancel()
	// Wait for the context to cancel
	time.Sleep(100 * time.Millisecond)

	newKeyPEM, _ := generateCAKey(t)
	replaceCAKeyFile(t, keyFile, newKeyPEM)
	time.Sleep(5 * time.Millisecond)

	signer := keyReloader.getSigner()
	require.NotNil(t, signer)
	assert.Equal(t, oldPublicKey.Marshal(), signer.PublicKey().Marshal())
}

func TestErrorInitializeKeyReloader(t *testing.T) {
	tests := []struct {
		name  string
		setup func(logger *zap.Logger) *keyReloader
	}{
		{
			name: "key file not found",
			setup: func(logger *zap.Logger) *keyReloader {
				return newKeyReloader("/nonexistent/ca", logger)
			},
		},
		{
			name: "invalid key file",
			setup: func(logger *zap.Logger) *keyReloader {
				return newKeyReloader(createCAKeyFile(t, []byte("not a private key")), logger)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				core, logs := observer.New(zapcore.DebugLevel)
				logger := zap.New(core)

				keyReloader := tt.setup(logger)
				keyReloader.Run(t.Context())

				synctest.Wait()

				allLogs := logs.All()
				require.NotEmpty(t, allLogs)

				log := allLogs[0]
				assert.Equal(t, zapcore.ErrorLevel, log.Level)
				assert.Equal(t, "failed to watch CA private key file, will retry later", log.Message)
			})
		})
	}
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
