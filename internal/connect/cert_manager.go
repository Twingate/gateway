// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

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

func (m *CertManager) Run(ctx context.Context) error {
	m.certs.Run(ctx)

	if m.automation != nil {
		if err := m.automation.Run(ctx); err != nil {
			return err
		}
	}

	return nil
}

// GetCertificate returns a certificate for the outer TLS handshake based on the SNI host, falling back to
// the connection's local IP for clients that send none (e.g. health probes).
func (m *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		var err error

		host, _, err = net.SplitHostPort(hello.Conn.LocalAddr().String())
		if err != nil {
			return nil, fmt.Errorf("failed to parse local address: %w", err)
		}
	}

	return m.GetCertificateForHost(hello, host)
}

// GetCertificateForHost returns a certificate based on given host.
// When the host is not covered by a configured certificate, it issues a new one on demand through the automation
// and includes the aliases as additional subject alternative names.
func (m *CertManager) GetCertificateForHost(hello *tls.ClientHelloInfo, host string, aliases ...string) (*tls.Certificate, error) {
	if m.automation == nil {
		return m.certs.GetCertificate(hello)
	}

	// No certificate is returned when certs is empty or no matching certificate is found
	// so we fall back to automation.
	if cert := m.certs.MatchCertificate(hello); cert != nil {
		return cert, nil
	}

	return m.automation.GetCertificateForHost(hello.Context(), host, aliases...)
}
