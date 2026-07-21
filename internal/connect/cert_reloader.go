// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"context"
	"crypto/tls"
	"sync"

	"go.uber.org/zap"

	"gateway/internal/reloader"
)

type CertReloader struct {
	certFile string
	keyFile  string
	logger   *zap.Logger

	mu   sync.RWMutex
	cert *tls.Certificate

	reloader *reloader.Reloader
}

func NewCertReloader(certFile, keyFile string, logger *zap.Logger) *CertReloader {
	cr := &CertReloader{
		certFile: certFile,
		keyFile:  keyFile,
		logger:   logger,
	}
	cr.reloader = reloader.New("cert and key file", logger, cr.load, certFile, keyFile)

	return cr
}

func (cr *CertReloader) Run(ctx context.Context) {
	cr.reloader.Run(ctx)
}

func (cr *CertReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
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
	cr.cert = &cert
	cr.mu.Unlock()

	cr.logger.Info("loaded cert and key files")

	return nil
}
