// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/util/wait"
)

// keyReloader watches the manual CA private key file and reloads the signer
// when the file changes, so the CA key can be rotated without a restart.
type keyReloader struct {
	keyFile string
	logger  *zap.Logger

	reloadCh chan struct{}

	mu     sync.RWMutex
	signer ssh.Signer
}

func newKeyReloader(keyFile string, logger *zap.Logger) *keyReloader {
	return &keyReloader{
		keyFile:  keyFile,
		logger:   logger,
		reloadCh: make(chan struct{}, 1),
	}
}

func (kr *keyReloader) Run(ctx context.Context) {
	go wait.Until(func() {
		if err := kr.watch(ctx); err != nil {
			kr.logger.Error("failed to watch CA private key file, will retry later", zap.Error(err))
		}
	}, time.Minute, ctx.Done())
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
		// Non-blocking send: a pending notification already re-signs with the latest key.
		select {
		case kr.reloadCh <- struct{}{}:
		default:
		}
	}

	return nil
}

func (kr *keyReloader) watch(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("error creating fsnotify watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(kr.keyFile); err != nil {
		return fmt.Errorf("error adding watch for file %s: %w", kr.keyFile, err)
	}

	if err := kr.load(); err != nil {
		return fmt.Errorf("error loading CA private key: %w", err)
	}

	kr.logger.Info("Start watching CA private key file changes")

	for {
		select {
		case event := <-watcher.Events:
			if err := kr.handleWatchEvent(event, watcher); err != nil {
				return err
			}
		case err := <-watcher.Errors:
			return fmt.Errorf("received error from watcher: %w", err)
		case <-ctx.Done():
			kr.logger.Info("Stopped watching CA private key file changes")

			return nil
		}
	}
}

func (kr *keyReloader) handleWatchEvent(event fsnotify.Event, watcher *fsnotify.Watcher) error {
	kr.logger.Debug("Received watch event", zap.Any("event", event))

	if !event.Has(fsnotify.Remove) && !event.Has(fsnotify.Rename) {
		if err := kr.load(); err != nil {
			kr.logger.Error("failed to load CA private key file", zap.Error(err))

			return nil
		}

		publicKeyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(kr.getSigner().PublicKey())))
		kr.logger.Info("reloaded CA private key file", zap.String("ca_public_key", publicKeyStr))

		return nil
	}

	if err := watcher.Remove(event.Name); err != nil {
		kr.logger.Info("failed to remove file watch, it may have been deleted", zap.Error(err))
	}

	err := watcher.Add(event.Name)

	return err
}
