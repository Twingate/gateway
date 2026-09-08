// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	lru "github.com/hashicorp/golang-lru/v2"

	"gateway/internal/config"
)

const (
	defaultTTL     = 24 * time.Hour
	maxCachedCerts = 1024
)

// automation issues short-lived certificates through the configured issuer.
// It caches one certificate per requested name and issues a fresh one once the
// cached certificate expires.
type automation struct {
	issuer issuer
	key    keyConfig
	ttl    time.Duration
	logger *zap.Logger

	mu sync.Mutex
	// counts CA rotations, so a certificate signed before one is not cached
	caRotations int
	cache       *lru.Cache[string, *tls.Certificate]
}

func newAutomation(cfg *config.TLSAutomationConfig, logger *zap.Logger) (*automation, error) {
	keyCfg, err := newKeyConfig(cfg.Certificate.Key.Type, cfg.Certificate.Key.Bits)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate key config: %w", err)
	}

	certTTL := cfg.Certificate.TTL
	if certTTL == 0 {
		certTTL = defaultTTL
	}

	issuer, err := newIssuer(cfg.Issuer, logger)
	if err != nil {
		return nil, err
	}

	cache, err := lru.New[string, *tls.Certificate](maxCachedCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate cache: %w", err)
	}

	return &automation{
		issuer: issuer,
		key:    keyCfg,
		ttl:    certTTL,
		logger: logger,
		cache:  cache,
	}, nil
}

func (a *automation) run(ctx context.Context) error {
	if err := a.issuer.run(ctx); err != nil {
		return err
	}

	// When the issuer can rotate its CA, drop the cached certificates as soon as
	// it does rather than serving ones that no longer chain to it.
	if issuer, ok := a.issuer.(rotatableIssuer); ok {
		go a.purgeOnRotation(ctx, issuer.rotated())
	}

	return nil
}

// getCertificateForHost issues a certificate covering the given host, caching it under that name.
func (a *automation) getCertificateForHost(ctx context.Context, host string) (*tls.Certificate, error) {
	host = strings.ToLower(host)

	if cert := a.cachedCert(host); cert != nil {
		return cert, nil
	}

	a.mu.Lock()
	rotations := a.caRotations
	a.mu.Unlock()

	// Sign outside the lock so a slow CA cannot stall handshakes for names that are already
	// cached. A burst against a cold cache may sign the same names twice, which is cheaper.
	cert, err := a.issue(ctx, host)
	if err != nil {
		return nil, err
	}

	a.logger.Debug("Issued downstream certificate",
		zap.String("host", host),
		zap.Time("not_after", cert.Leaf.NotAfter),
	)

	a.mu.Lock()
	defer a.mu.Unlock()

	// The CA rotated while this certificate was in flight: serve it to this handshake
	// only, so the cache never holds a certificate from a previous CA.
	if rotations == a.caRotations {
		a.cache.Add(host, cert)
	}

	return cert, nil
}

func (a *automation) issue(ctx context.Context, name string) (*tls.Certificate, error) {
	key, err := a.key.generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}

	leaf, caChain, err := a.issuer.sign(ctx, newCertificateRequest(key, name, a.ttl))
	if err != nil {
		return nil, err
	}

	chain := make([][]byte, 0, len(caChain)+1)
	chain = append(chain, leaf.Raw)

	for _, ca := range caChain {
		chain = append(chain, ca.Raw)
	}

	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func (a *automation) purgeOnRotation(ctx context.Context, rotated <-chan struct{}) {
	for {
		select {
		case <-rotated:
			a.mu.Lock()
			a.caRotations++
			purged := a.cache.Len()
			a.cache.Purge()
			a.mu.Unlock()

			a.logger.Info("Dropped cached downstream certificates after CA rotation", zap.Int("certificates", purged))
		case <-ctx.Done():
			return
		}
	}
}

func (a *automation) cachedCert(key string) *tls.Certificate {
	cert, ok := a.cache.Get(key)
	if !ok {
		return nil
	}

	if time.Now().Before(cert.Leaf.NotAfter) {
		return cert
	}

	return nil
}

type certificateRequest struct {
	key         crypto.Signer
	dnsNames    []string
	ipAddresses []net.IP
	ttl         time.Duration
}

func newCertificateRequest(key crypto.Signer, name string, ttl time.Duration) *certificateRequest {
	req := &certificateRequest{key: key, ttl: ttl}

	// A handshake without SNI leaves no name, and the certificate then covers none.
	if ip := net.ParseIP(name); ip != nil {
		req.ipAddresses = []net.IP{ip}
	} else if name != "" {
		req.dnsNames = []string{name}
	}

	return req
}

// csr builds the request DER-encoded and signed by the leaf key.
func (c *certificateRequest) csr() ([]byte, error) {
	template := &x509.CertificateRequest{DNSNames: c.dnsNames, IPAddresses: c.ipAddresses}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	return csr, nil
}
