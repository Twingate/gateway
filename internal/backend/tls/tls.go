// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

// Package tls builds the TLS client settings the backends use toward their upstreams, from
// the upstream TLS mode in the GAT and the CA bundles in the config.
package tls

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	cryptotls "crypto/tls"

	"gateway/internal/config"
	"gateway/internal/token"
)

var (
	errInvalidCACert     = errors.New("failed to parse CA certificate")
	errNoPeerCertificate = errors.New("upstream presented no certificate")
)

// NewCAPool merges the configured CAs on top of the system cert pool to verify
// upstream TLS connections, so publicly-signed upstreams work without configuration.
func NewCAPool(caBundles []config.UpstreamTrustedCABundle) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system cert pool: %w", err)
	}

	for _, caBundle := range caBundles {
		caCerts, err := os.ReadFile(caBundle.File) //nolint:gosec // The CA bundle file is provided by the operator
		if err != nil {
			return nil, fmt.Errorf("ca %q: %w", caBundle.File, err)
		}

		if ok := pool.AppendCertsFromPEM(caCerts); !ok {
			return nil, fmt.Errorf("ca %q: %w", caBundle.File, errInvalidCACert)
		}
	}

	return pool, nil
}

// NewUpstreamTLSConfig returns the TLS client config for connecting to an upstream in the given
// mode, verifying certificate chains against rootCAs. It returns nil for TLSClientModeNone.
func NewUpstreamTLSConfig(mode token.TLSClientMode, rootCAs *x509.CertPool) *cryptotls.Config {
	switch mode {
	case token.TLSClientModeNone:
		return nil
	case token.TLSClientModeInsecure:
		return &cryptotls.Config{
			MinVersion:         cryptotls.VersionTLS13,
			InsecureSkipVerify: true, // #nosec G402 -- The resource explicitly opts out of upstream certificate verification
		}
	case token.TLSClientModeVerifyCA:
		// Disable the built-in verification, which always checks the hostname, and verify only the
		// certificate chain in VerifyConnection.
		return &cryptotls.Config{
			MinVersion:         cryptotls.VersionTLS13,
			InsecureSkipVerify: true, // #nosec G402 -- The certificate chain is verified in VerifyConnection
			VerifyConnection:   verifyCertificateChain(rootCAs),
		}
	case token.TLSClientModeVerifyFull:
		fallthrough
	default:
		return &cryptotls.Config{
			MinVersion: cryptotls.VersionTLS13,
			RootCAs:    rootCAs,
		}
	}
}

// verifyCertificateChain returns a VerifyConnection callback that verifies the peer's certificate
// chain against rootCAs without checking the hostname.
func verifyCertificateChain(rootCAs *x509.CertPool) func(cryptotls.ConnectionState) error {
	return func(cs cryptotls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errNoPeerCertificate
		}

		opts := x509.VerifyOptions{
			Roots:         rootCAs,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}

		if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
			return fmt.Errorf("verify upstream certificate: %w", err)
		}

		return nil
	}
}
