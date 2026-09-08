// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"crypto/tls"
	"sync"

	"go.uber.org/zap"

	"gateway/internal/config"
	filereloader "gateway/internal/reloader"
)

type reloader struct {
	logger   *zap.Logger
	keyPairs []config.TLSCertificateFileKeyPair

	mu    sync.RWMutex
	certs map[string]*tls.Certificate

	reloaders []*filereloader.Reloader
}

func newReloader(keyPairs []config.TLSCertificateFileKeyPair, logger *zap.Logger) *reloader {
	cr := &reloader{
		logger:    logger,
		keyPairs:  keyPairs,
		certs:     make(map[string]*tls.Certificate, len(keyPairs)),
		reloaders: make([]*filereloader.Reloader, 0, len(keyPairs)),
	}

	for _, keyPair := range keyPairs {
		load := func() error { return cr.load(keyPair) }
		cr.reloaders = append(cr.reloaders, filereloader.New([]string{keyPair.CertificateFile, keyPair.PrivateKeyFile}, load, logger))
	}

	return cr
}

func (cr *reloader) run(ctx context.Context) {
	for _, r := range cr.reloaders {
		r.Run(ctx)
	}
}

// match returns the first certificate in configuration order that the client supports.
func (cr *reloader) match(hello *tls.ClientHelloInfo) *tls.Certificate {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	for _, keyPair := range cr.keyPairs {
		cert, ok := cr.certs[keyPair.CertificateFile]
		if !ok {
			continue
		}

		if err := hello.SupportsCertificate(cert); err == nil {
			return cert
		}
	}

	return nil
}

// first returns the first loaded certificate in configuration order.
func (cr *reloader) first() *tls.Certificate {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	for _, keyPair := range cr.keyPairs {
		if cert, ok := cr.certs[keyPair.CertificateFile]; ok {
			return cert
		}
	}

	return nil
}

func (cr *reloader) load(keyPair config.TLSCertificateFileKeyPair) error {
	cert, err := tls.LoadX509KeyPair(keyPair.CertificateFile, keyPair.PrivateKeyFile)
	if err != nil {
		return err
	}

	cr.mu.Lock()
	cr.certs[keyPair.CertificateFile] = &cert
	cr.mu.Unlock()

	cr.logger.Info("loaded cert and key files", zap.String("certificateFile", keyPair.CertificateFile))

	return nil
}
