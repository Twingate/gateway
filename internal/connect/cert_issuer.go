// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"gateway/internal/config"
	"gateway/internal/reloader"
)

const clockSkewBuffer = 30 * time.Second

var (
	errNotCACertificate = errors.New("certificate is not a certificate authority")
	errCAKeyNotSigner   = errors.New("CA private key does not implement crypto.Signer")
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// certIssuer issues a certificate covering a set of names and runs any
// background maintenance its backend needs.
type certIssuer interface {
	run(ctx context.Context)
	issue(ctx context.Context, names []string) (*tls.Certificate, error)
}

// rotatableIssuer is a certIssuer whose CA can rotate during the process lifetime.
// The channel returned by rotated receives a value after each rotation.
type rotatableIssuer interface {
	rotated() <-chan struct{}
}

func newCertIssuer(cfg config.TLSIssuerConfig, keyCfg keyConfig, ttl time.Duration, logger *zap.Logger) (certIssuer, error) {
	switch {
	case cfg.Local != nil:
		return newLocalIssuer(cfg.Local, keyCfg, ttl, logger)
	default:
		return nil, config.ErrMissingTLSIssuerConfig
	}
}

// localIssuer signs certificates locally with a CA loaded from files, reloading
// them on change so the CA can be rotated without a restart.
type localIssuer struct {
	certFile string
	keyFile  string
	key      keyConfig
	ttl      time.Duration
	logger   *zap.Logger

	rotateCh chan struct{} // Receives a value after each CA rotation (implements rotatableIssuer)

	mu     sync.RWMutex
	caCert *x509.Certificate
	caKey  crypto.Signer

	reloader *reloader.Reloader
}

func newLocalIssuer(cfg *config.TLSLocalIssuerConfig, keyCfg keyConfig, ttl time.Duration, logger *zap.Logger) (*localIssuer, error) {
	issuer := &localIssuer{
		certFile: cfg.CertificateFile,
		keyFile:  cfg.PrivateKeyFile,
		key:      keyCfg,
		ttl:      ttl,
		logger:   logger,
		rotateCh: make(chan struct{}, 1),
	}
	issuer.reloader = reloader.New([]string{cfg.CertificateFile, cfg.PrivateKeyFile}, issuer.load, logger)

	// Load up front so a misconfigured issuer fails at startup.
	if err := issuer.load(); err != nil {
		return nil, err
	}

	return issuer, nil
}

func (l *localIssuer) run(ctx context.Context) {
	l.reloader.Run(ctx)
}

func (l *localIssuer) rotated() <-chan struct{} {
	return l.rotateCh
}

func (l *localIssuer) load() error {
	pair, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
	if err != nil {
		return fmt.Errorf("failed to load CA key pair: %w", err)
	}

	caCert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	if !caCert.IsCA {
		return fmt.Errorf("%w: %q", errNotCACertificate, l.certFile)
	}

	caKey, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("%w: %q", errCAKeyNotSigner, l.keyFile)
	}

	l.mu.Lock()
	previous := l.caCert
	l.caCert = caCert
	l.caKey = caKey
	l.mu.Unlock()

	// The reloader loads again when it starts watching, so only a different CA
	// counts as a rotation.
	if previous == nil || bytes.Equal(previous.Raw, caCert.Raw) {
		return nil
	}

	l.logger.Info("Reloaded CA certificate and key files", zap.String("certificateFile", l.certFile))

	// Non-blocking send: a pending notification already covers the latest CA.
	select {
	case l.rotateCh <- struct{}{}:
	default:
	}

	return nil
}

func (l *localIssuer) issue(_ context.Context, names []string) (*tls.Certificate, error) {
	key, err := l.key.generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	l.mu.RLock()
	caCert, caKey := l.caCert, l.caKey
	l.mu.RUnlock()

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    now.Add(-clockSkewBuffer),
		NotAfter:     now.Add(l.ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, caCert, key.Public(), caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign leaf certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{leafDER, caCert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}
