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

// CertProvider supplies the downstream serving certificates and runs any
// background maintenance (file watching in static mode).
type CertProvider interface {
	// Run runs background maintenance until the context is canceled.
	Run(ctx context.Context)

	// GetCertificate serves the outer, pre-CONNECT handshake.
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)

	// GetCertificateForHost returns the certificate presented for the
	// validated CONNECT host on the inner handshake.
	GetCertificateForHost(host string) (*tls.Certificate, error)
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
