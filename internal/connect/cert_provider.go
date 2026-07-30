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

// CertProvider supplies the downstream serving certificates and runs any
// background maintenance (file watching in static mode).
type CertProvider interface {
	// Run runs background maintenance until the context is canceled.
	Run(ctx context.Context)

	// GetCertificateForHost returns the certificate presented for the given
	// host: the SNI host on the outer TLS, the validated CONNECT host
	// on the inner TLS.
	//
	// Note: SNI cannot carry an IP address (see RFC 6066 § 3)
	GetCertificateForHost(host string) (*tls.Certificate, error)
}

// getCertificateForHello serves the outer TLS handshake when the SNI
// host is present, falling back to the connection's local IP for clients
// that send none (e.g. IP-dialed clients and health probes).
func getCertificateForHello(provider CertProvider, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		var err error

		host, _, err = net.SplitHostPort(hello.Conn.LocalAddr().String())
		if err != nil {
			return nil, fmt.Errorf("failed to parse local address: %w", err)
		}
	}

	return provider.GetCertificateForHost(host)
}

// newCertProviderFromConfig creates a CertProvider based on the provided
// configuration.
func newCertProviderFromConfig(tlsCfg config.TLSConfig, logger *zap.Logger) (CertProvider, error) {
	switch {
	case tlsCfg.Static != nil:
		return NewCertReloader(tlsCfg.Static.CertificateFile, tlsCfg.Static.PrivateKeyFile, logger), nil
	case tlsCfg.Dynamic != nil:
		dynamicCert, err := NewDynamicCert(*tlsCfg.Dynamic, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create dynamic cert: %w", err)
		}

		return dynamicCert, nil
	default:
		return nil, config.ErrMissingTLSConfig
	}
}
