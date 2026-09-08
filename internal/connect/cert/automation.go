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
// It caches one certificate per requested name set and issues a fresh one once the
// cached certificate expires.
type automation struct {
	issuer issuer
	key    keyConfig
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

	issuer, err := newIssuer(cfg.Issuer, certTTL, logger)
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
		logger: logger,
		cache:  cache,
	}, nil
}

func (c *automation) run(ctx context.Context) error {
	if err := c.issuer.run(ctx); err != nil {
		return err
	}

	// When the issuer can rotate its CA, drop the cached certificates as soon as
	// it does rather than serving ones that no longer chain to it.
	if issuer, ok := c.issuer.(rotatableIssuer); ok {
		go c.purgeOnRotation(ctx, issuer.rotated())
	}

	return nil
}

// getCertificateForHost issues a certificate covering the given host, caching it under that name.
func (c *automation) getCertificateForHost(ctx context.Context, host string) (*tls.Certificate, error) {
	host = strings.ToLower(host)

	if cert := c.cachedCert(host); cert != nil {
		return cert, nil
	}

	c.mu.Lock()
	rotations := c.caRotations
	c.mu.Unlock()

	// Sign outside the lock so a slow CA cannot stall handshakes for names that are already
	// cached. A burst against a cold cache may sign the same names twice, which is cheaper.
	cert, err := c.issue(ctx, host)
	if err != nil {
		return nil, err
	}

	c.logger.Debug("Issued downstream certificate",
		zap.String("host", host),
		zap.Time("not_after", cert.Leaf.NotAfter),
	)

	c.mu.Lock()
	defer c.mu.Unlock()

	// The CA rotated while this certificate was in flight: serve it to this handshake
	// only, so the cache never holds a certificate from a previous CA.
	if rotations == c.caRotations {
		c.cache.Add(host, cert)
	}

	return cert, nil
}

// issue generates a leaf key and has the issuer's CA sign a request covering name,
// assembling the certificate served on the handshake.
func (c *automation) issue(ctx context.Context, name string) (*tls.Certificate, error) {
	key, err := c.key.generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}

	csr, err := certificateRequest(key, name)
	if err != nil {
		return nil, err
	}

	leaf, caChain, err := c.issuer.sign(ctx, csr)
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

// purgeOnRotation drops every cached certificate and counts the rotation.
func (c *automation) purgeOnRotation(ctx context.Context, rotated <-chan struct{}) {
	for {
		select {
		case <-rotated:
			c.mu.Lock()
			c.caRotations++
			purged := c.cache.Len()
			c.cache.Purge()
			c.mu.Unlock()

			c.logger.Info("Dropped cached downstream certificates after CA rotation", zap.Int("certificates", purged))
		case <-ctx.Done():
			return
		}
	}
}

func (c *automation) cachedCert(key string) *tls.Certificate {
	cert, ok := c.cache.Get(key)
	if !ok {
		return nil
	}

	if time.Now().Before(cert.Leaf.NotAfter) {
		return cert
	}

	return nil
}

// certificateRequest builds a DER-encoded certificate request covering name, signed by
// key so a backend can forward it to a remote CA.
func certificateRequest(key crypto.Signer, name string) ([]byte, error) {
	template := &x509.CertificateRequest{}

	// A handshake without SNI leaves no name, and the certificate then covers none.
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else if name != "" {
		template.DNSNames = []string{name}
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	return der, nil
}
