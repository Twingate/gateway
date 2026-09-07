// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"context"
	"crypto/tls"
	"fmt"

	"go.uber.org/zap"

	"gateway/internal/config"
)

// CertManager returns the certificate served on a downstream TLS handshake.
type CertManager struct {
	certs      *CertReloader
	automation *CertAutomation
}

func newCertManager(tlsCfg config.TLSConfig, logger *zap.Logger) (*CertManager, error) {
	manager := &CertManager{certs: NewCertReloader(tlsCfg.Certificates.Files, logger)}

	if tlsCfg.Automation != nil {
		automation, err := NewCertAutomation(*tlsCfg.Automation, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create cert automation: %w", err)
		}

		manager.automation = automation
	}

	return manager, nil
}

func (m *CertManager) Run(ctx context.Context) {
	m.certs.Run(ctx)

	if m.automation != nil {
		m.automation.Run(ctx)
	}
}

// GetCertificate returns the certificate for a downstream TLS handshake.
func (m *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.automation == nil {
		return m.certs.GetCertificate(hello)
	}

	// No certificate is returned when certs is empty or no matching certificate is found
	// so we fall back to automation.
	if cert := m.certs.MatchCertificate(hello); cert != nil {
		return cert, nil
	}

	return m.automation.GetCertificateForHost(hello.Context(), hello.ServerName)
}
