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
	"slices"
	"strings"
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

// DynamicCert issues short-lived leaf certificates through the configured
// issuer, caching one certificate per requested name set and re-issuing a
// fresh one once the cached certificate enters the renewal window.
type DynamicCert struct {
	issuer certIssuer
	cert   config.TLSDynamicCertConfig
	logger *zap.Logger

	mu    sync.Mutex
	cache *lru.Cache[string, *tls.Certificate]
}

func NewDynamicCert(cfg config.TLSDynamicConfig, logger *zap.Logger) (*DynamicCert, error) {
	issuer, err := newCertIssuer(cfg)
	if err != nil {
		return nil, err
	}

	cache, err := lru.New[string, *tls.Certificate](maxCachedCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate cache: %w", err)
	}

	return &DynamicCert{
		issuer: issuer,
		cert:   cfg.Cert,
		logger: logger,
		cache:  cache,
	}, nil
}

// certIssuer issues a certificate covering a set of names and runs any
// background maintenance its backend needs.
type certIssuer interface {
	run(ctx context.Context)
	issue(ctx context.Context, names []string) (*tls.Certificate, error)
}

func newCertIssuer(cfg config.TLSDynamicConfig) (certIssuer, error) {
	switch {
	case cfg.CA.SelfSign != nil:
		return newSelfSignIssuer(cfg.CA.SelfSign, cfg.Cert)
	default:
		return nil, config.ErrMissingTLSCAConfig
	}
}

// Run implements CertProvider, delegating background maintenance to the issuer.
func (c *DynamicCert) Run(ctx context.Context) {
	c.issuer.run(ctx)
}

// GetCertificateForHost returns a certificate covering host and aliases,
// issuing a new one when none is cached or the cached one is inside the
// renewal window.
func (c *DynamicCert) GetCertificateForHost(ctx context.Context, host string, aliases ...string) (*tls.Certificate, error) {
	names := certNames(host, aliases)
	key := strings.Join(names, ",")

	if cert, ok := c.cachedCert(key); ok {
		return cert, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check under the lock: a caller ahead in the queue may have issued
	// this host already, which keeps concurrent cold misses to one issuance.
	if cert, ok := c.cachedCert(key); ok {
		return cert, nil
	}

	cert, err := c.issuer.issue(ctx, names)
	if err != nil {
		return nil, err
	}

	c.logger.Debug("Issued downstream certificate",
		zap.Strings("hosts", names),
		zap.Time("not_after", cert.Leaf.NotAfter),
	)

	c.cache.Add(key, cert)

	return cert, nil
}

// certNames is host followed by its aliases, sorted and without duplicates,
// so the same name set always yields the same cache key. host stays first so
// it becomes the common name.
func certNames(host string, aliases []string) []string {
	names := make([]string, 0, len(aliases)+1)
	names = append(names, host)

	for _, alias := range aliases {
		if alias != "" && !slices.Contains(names, alias) {
			names = append(names, alias)
		}
	}

	slices.Sort(names[1:])

	return names
}

// cachedCert returns the cached certificate for the given name set
// while it is outside the renewal window.
func (c *DynamicCert) cachedCert(key string) (*tls.Certificate, bool) {
	cert, ok := c.cache.Get(key)
	if !ok {
		return nil, false
	}

	return cert, time.Now().Before(cert.Leaf.NotAfter.Add(-c.cert.GetRenewBefore()))
}

// selfSignIssuer signs leaf certificates locally with a CA loaded from files.
type selfSignIssuer struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	cert   config.TLSDynamicCertConfig
}

func newSelfSignIssuer(cfg *config.TLSSelfSignCAConfig, certCfg config.TLSDynamicCertConfig) (*selfSignIssuer, error) {
	pair, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.PrivateKeyFile)
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

	return &selfSignIssuer{caCert: caCert, caKey: caKey, cert: certCfg}, nil
}

// run implements certIssuer; the self-sign backend has no background maintenance.
func (s *selfSignIssuer) run(_ context.Context) {}

func (s *selfSignIssuer) issue(_ context.Context, names []string) (*tls.Certificate, error) {
	key, err := s.generateKey()
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
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    now.Add(-clockSkewBuffer),
		NotAfter:     now.Add(s.cert.GetDuration()),
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

	leafDER, err := x509.CreateCertificate(rand.Reader, template, s.caCert, key.Public(), s.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign leaf certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{leafDER, s.caCert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func (s *selfSignIssuer) generateKey() (crypto.Signer, error) {
	switch s.cert.GetKeyType() {
	case "ecdsa":
		switch s.cert.GetKeyBits() {
		case 256:
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case 384:
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case 521:
			return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			return nil, fmt.Errorf("%w: ECDSA %d", errUnsupportedKeyBits, s.cert.GetKeyBits())
		}
	case "rsa":
		return rsa.GenerateKey(rand.Reader, s.cert.GetKeyBits())
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedKeyType, s.cert.GetKeyType())
	}
}
