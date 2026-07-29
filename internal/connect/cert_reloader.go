// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/wait"
)

type CertReloader struct {
	certFile string
	keyFile  string
	logger   *zap.Logger

	mu   sync.RWMutex
	cert *tls.Certificate
}

func NewCertReloader(certFile, keyFile string, logger *zap.Logger) *CertReloader {
	return &CertReloader{
		certFile: certFile,
		keyFile:  keyFile,
		logger:   logger,
	}
}

func (cr *CertReloader) Run(ctx context.Context) {
	go wait.Until(func() {
		if err := cr.watch(ctx); err != nil {
			cr.logger.Error("failed to watch cert and key file, will retry later", zap.Error(err))
		}
	}, time.Minute, ctx.Done())
}

func (cr *CertReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cr.GetCertificateForHost("")
}

// GetCertificateForHost implements CertProvider, the configured certificate is
// served regardless of the requested host.
func (cr *CertReloader) GetCertificateForHost(_ string) (*tls.Certificate, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	return cr.cert, nil
}

func (cr *CertReloader) load() error {
	cert, err := tls.LoadX509KeyPair(cr.certFile, cr.keyFile)
	if err != nil {
		return err
	}

	cr.mu.Lock()
	defer cr.mu.Unlock()

	cr.cert = &cert

	return nil
}

func (cr *CertReloader) watch(ctx context.Context) error {
	var err error

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("error creating fsnotify watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(cr.certFile); err != nil {
		return fmt.Errorf("error adding watch for file %s: %w", cr.certFile, err)
	}

	if err := watcher.Add(cr.keyFile); err != nil {
		return fmt.Errorf("error adding watch for file %s: %w", cr.keyFile, err)
	}

	if err := cr.load(); err != nil {
		return fmt.Errorf("error loading certificate: %w", err)
	}

	cr.logger.Info("Start watching cert and key files changes")

	for {
		select {
		case event := <-watcher.Events:
			if err := cr.handleWatchEvent(event, watcher); err != nil {
				return err
			}
		case err := <-watcher.Errors:
			return fmt.Errorf("received error from watcher: %w", err)
		case <-ctx.Done():
			cr.logger.Info("Stopped watching cert and key files changes")

			return nil
		}
	}
}

func (cr *CertReloader) handleWatchEvent(event fsnotify.Event, watcher *fsnotify.Watcher) error {
	cr.logger.Debug("Received watch event", zap.Any("event", event))

	if !event.Has(fsnotify.Remove) && !event.Has(fsnotify.Rename) {
		if err := cr.load(); err != nil {
			cr.logger.Error("failed to load cert or key file", zap.Error(err))

			return nil
		}

		cr.logger.Info("reloaded cert and key files")

		return nil
	}

	if err := watcher.Remove(event.Name); err != nil {
		cr.logger.Info("failed to remove file watch, it may have been deleted", zap.Error(err))
	}

	err := watcher.Add(event.Name)

	return err
}
