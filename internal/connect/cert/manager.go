// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"crypto/tls"
	"fmt"

	"go.uber.org/zap"

	"gateway/internal/config"
)

// Manager returns the certificate served on a downstream TLS handshake.
type Manager struct {
	certs      *reloader
	automation *automation
}

func NewManager(tlsCfg config.TLSConfig, logger *zap.Logger) (*Manager, error) {
	var keyPairs []config.TLSCertificateFileKeyPair
	if tlsCfg.Certificates != nil {
		keyPairs = tlsCfg.Certificates.Files
	}

	manager := &Manager{certs: newReloader(keyPairs, logger)}

	if tlsCfg.Automation != nil {
		automation, err := newAutomation(*tlsCfg.Automation, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create cert automation: %w", err)
		}

		manager.automation = automation
	}

	return manager, nil
}

func (m *Manager) Run(ctx context.Context) error {
	m.certs.Run(ctx)

	if m.automation != nil {
		if err := m.automation.Run(ctx); err != nil {
			return err
		}
	}

	return nil
}

// GetCertificate returns the certificate for a downstream TLS handshake.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
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
