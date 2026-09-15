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
	r := &reloader{
		logger:    logger,
		keyPairs:  keyPairs,
		certs:     make(map[string]*tls.Certificate, len(keyPairs)),
		reloaders: make([]*filereloader.Reloader, 0, len(keyPairs)),
	}

	for _, keyPair := range keyPairs {
		load := func() error { return r.load(keyPair) }
		r.reloaders = append(r.reloaders, filereloader.New([]string{keyPair.CertificateFile, keyPair.PrivateKeyFile}, load, logger))
	}

	return r
}

func (r *reloader) run(ctx context.Context) {
	for _, fr := range r.reloaders {
		fr.Run(ctx)
	}
}

// match returns the first certificate in configuration order that can serve this ClientHello.
func (r *reloader) match(hello *tls.ClientHelloInfo) *tls.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, keyPair := range r.keyPairs {
		cert, ok := r.certs[keyPair.CertificateFile]
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
func (r *reloader) first() *tls.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, keyPair := range r.keyPairs {
		if cert, ok := r.certs[keyPair.CertificateFile]; ok {
			return cert
		}
	}

	return nil
}

func (r *reloader) load(keyPair config.TLSCertificateFileKeyPair) error {
	cert, err := tls.LoadX509KeyPair(keyPair.CertificateFile, keyPair.PrivateKeyFile)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.certs[keyPair.CertificateFile] = &cert
	r.mu.Unlock()

	r.logger.Info("loaded cert and key files", zap.String("certificateFile", keyPair.CertificateFile))

	return nil
}
