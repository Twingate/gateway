// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"

	"go.uber.org/zap"

	"gateway/internal/config"
	filereloader "gateway/internal/reloader"
)

// ErrNoCertificates is returned when no certificate has been loaded.
var ErrNoCertificates = errors.New("no certificate could be loaded")

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

func (cr *reloader) Run(ctx context.Context) {
	for _, r := range cr.reloaders {
		r.Run(ctx)
	}
}

// GetCertificate returns the first certificate the client supports, falling back to the
// first loaded certificate when none of them matches.
func (cr *reloader) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cert := cr.MatchCertificate(hello); cert != nil {
		return cert, nil
	}

	if cert := cr.firstCertificate(); cert != nil {
		return cert, nil
	}

	return nil, ErrNoCertificates
}

// MatchCertificate returns the first certificate the client supports, or nil when
// none of them matches.
func (cr *reloader) MatchCertificate(hello *tls.ClientHelloInfo) *tls.Certificate {
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

// firstCertificate returns the first loaded certificate, in configuration order,
// or nil when none is loaded.
func (cr *reloader) firstCertificate() *tls.Certificate {
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
