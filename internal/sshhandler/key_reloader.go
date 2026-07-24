// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"strings"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"gateway/internal/reloader"
)

// keyReloader loads the manual CA private key and swaps the signer when the key
// file changes, so the CA key can be rotated without a restart.
type keyReloader struct {
	keyFile string
	logger  *zap.Logger

	reloadCh chan struct{}

	mu     sync.RWMutex
	signer ssh.Signer

	reloader *reloader.Reloader
}

func newKeyReloader(keyFile string, logger *zap.Logger) *keyReloader {
	kr := &keyReloader{
		keyFile:  keyFile,
		logger:   logger,
		reloadCh: make(chan struct{}, 1),
	}
	kr.reloader = reloader.New("CA private key file", logger, kr.load, keyFile)

	return kr
}

func (kr *keyReloader) Run(ctx context.Context) {
	kr.reloader.Run(ctx)
}

func (kr *keyReloader) getSigner() ssh.Signer {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	return kr.signer
}

func (kr *keyReloader) load() error {
	signer, err := loadPrivateKey(kr.keyFile)
	if err != nil {
		return err
	}

	kr.mu.Lock()
	previous := kr.signer
	kr.signer = signer
	kr.mu.Unlock()

	if previous != nil && !keysEqual(previous.PublicKey(), signer.PublicKey()) {
		publicKeyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
		kr.logger.Info("reloaded CA private key file", zap.String("ca_public_key", publicKeyStr))

		// Non-blocking send: a pending notification already re-signs with the latest key.
		select {
		case kr.reloadCh <- struct{}{}:
		default:
		}
	}

	return nil
}
