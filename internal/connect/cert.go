// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

	lru "github.com/hashicorp/golang-lru/v2"

	"gateway/internal/config"
)

const (
	clockSkewBuffer = 30 * time.Second
	maxCachedCerts  = 1024
)

var (
	errNotCACertificate   = errors.New("certificate is not a certificate authority")
	errCAKeyNotSigner     = errors.New("CA private key does not implement crypto.Signer")
	errUnsupportedKeyType = errors.New("unsupported key type")
	errUnsupportedKeyBits = errors.New("unsupported key bits")
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// DynamicCert mints short-lived leaf certificates signed by the configured
// CA, caching one certificate per requested host and re-minting a fresh one
// once the cached certificate enters the renewal window.
type DynamicCert struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	cert   config.TLSDynamicCertConfig
	logger *zap.Logger

	mu    sync.Mutex
	cache *lru.Cache[string, *tls.Certificate]
}

func NewDynamicCert(cfg config.TLSDynamicConfig, logger *zap.Logger) (*DynamicCert, error) {
	if cfg.CA.SelfSign == nil {
		return nil, config.ErrMissingTLSCAConfig
	}

	pair, err := tls.LoadX509KeyPair(cfg.CA.SelfSign.CertificateFile, cfg.CA.SelfSign.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA key pair: %w", err)
	}

	caCert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	if !caCert.IsCA {
		return nil, errNotCACertificate
	}

	caKey, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errCAKeyNotSigner
	}

	cache, err := lru.New[string, *tls.Certificate](maxCachedCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate cache: %w", err)
	}

	return &DynamicCert{
		caCert: caCert,
		caKey:  caKey,
		cert:   cfg.Cert,
		logger: logger,
		cache:  cache,
	}, nil
}

// Run implements CertProvider; dynamic mode has no background maintenance.
func (c *DynamicCert) Run(_ context.Context) {}

// GetCertificateForHost returns a certificate for the requested host, minting
// a new one when none is cached or the cached one is inside the renewal window.
func (c *DynamicCert) GetCertificateForHost(host string) (*tls.Certificate, error) {
	if cert, ok := c.cachedCert(host); ok {
		return cert, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check under the lock: a caller ahead in the queue may have minted
	// this host already, which keeps concurrent cold misses to one mint.
	if cert, ok := c.cachedCert(host); ok {
		return cert, nil
	}

	cert, err := c.mint(host)
	if err != nil {
		return nil, err
	}

	c.cache.Add(host, cert)

	return cert, nil
}

// cachedCert returns the cached certificate for the given host
// while it is outside the renewal window.
func (c *DynamicCert) cachedCert(host string) (*tls.Certificate, bool) {
	cert, ok := c.cache.Get(host)
	if !ok {
		return nil, false
	}

	return cert, time.Now().Before(cert.Leaf.NotAfter.Add(-c.cert.GetRenewBefore()))
}

func (c *DynamicCert) mint(host string) (*tls.Certificate, error) {
	key, err := c.generateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-clockSkewBuffer),
		NotAfter:     now.Add(c.cert.GetDuration()),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, c.caCert, key.Public(), c.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign leaf certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	c.logger.Info("Minted downstream certificate",
		zap.String("host", host),
		zap.Time("not_after", leaf.NotAfter),
	)

	return &tls.Certificate{
		Certificate: [][]byte{leafDER, c.caCert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func (c *DynamicCert) generateKey() (crypto.Signer, error) {
	switch c.cert.GetKeyType() {
	case "ecdsa":
		switch c.cert.GetKeyBits() {
		case 256:
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case 384:
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case 521:
			return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			return nil, fmt.Errorf("%w: ECDSA %d", errUnsupportedKeyBits, c.cert.GetKeyBits())
		}
	case "rsa":
		return rsa.GenerateKey(rand.Reader, c.cert.GetKeyBits())
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedKeyType, c.cert.GetKeyType())
	}
}
