// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"context"
	"crypto/tls"
	"sync"

	"go.uber.org/zap"

	"gateway/internal/config"
	"gateway/internal/reloader"
)

type CertReloader struct {
	logger *zap.Logger
	files  []config.TLSCertificateFile

	mu    sync.RWMutex
	certs map[string]*tls.Certificate

	reloaders []*reloader.Reloader
}

func NewCertReloader(files []config.TLSCertificateFile, logger *zap.Logger) *CertReloader {
	cr := &CertReloader{
		logger:    logger,
		files:     files,
		certs:     make(map[string]*tls.Certificate, len(files)),
		reloaders: make([]*reloader.Reloader, 0, len(files)),
	}

	for _, file := range files {
		load := func() error { return cr.load(file) }
		cr.reloaders = append(cr.reloaders, reloader.New([]string{file.CertificateFile, file.PrivateKeyFile}, load, logger))
	}

	return cr
}

func (cr *CertReloader) Run(ctx context.Context) {
	for _, r := range cr.reloaders {
		r.Run(ctx)
	}
}

// GetCertificate returns the first certificate the client supports, falling back to the
// first certificate when none of them matches.
func (cr *CertReloader) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	for _, file := range cr.files {
		cert, ok := cr.certs[file.CertificateFile]
		if !ok {
			continue
		}

		if err := hello.SupportsCertificate(cert); err == nil {
			return cert, nil
		}
	}

	// If nothing matches, return the first certificate.
	return cr.certs[cr.files[0].CertificateFile], nil
}

func (cr *CertReloader) load(file config.TLSCertificateFile) error {
	cert, err := tls.LoadX509KeyPair(file.CertificateFile, file.PrivateKeyFile)
	if err != nil {
		return err
	}

	cr.mu.Lock()
	cr.certs[file.CertificateFile] = &cert
	cr.mu.Unlock()

	cr.logger.Info("loaded cert and key files", zap.String("certificateFile", file.CertificateFile))

	return nil
}
