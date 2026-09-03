// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"context"
	"crypto/tls"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	lru "github.com/hashicorp/golang-lru/v2"

	"gateway/internal/config"
)

const (
	defaultCertTTL = 24 * time.Hour

	maxCachedCerts = 1024

	// renewFraction is the fraction of a certificate's lifetime after which the
	// next handshake issues a fresh one.
	renewFraction = 0.8
)

// CertAutomation issues short-lived certificates through the configured issuer.
// It caches one certificate per requested name set and issues a fresh one once the
// cached certificate is past its renewal threshold.
type CertAutomation struct {
	issuer certIssuer
	logger *zap.Logger

	mu          sync.Mutex // orders cache writes against rotation purges
	caRotations int        // counts CA rotations, so a certificate signed before one is not cached
	cache       *lru.Cache[string, *tls.Certificate]
}

func NewCertAutomation(cfg config.TLSAutomationConfig, logger *zap.Logger) (*CertAutomation, error) {
	keyCfg, err := newKeyConfig(cfg.Certificate.Key.Type, cfg.Certificate.Key.Bits)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate key config: %w", err)
	}

	certTTL := cfg.Certificate.TTL
	if certTTL == 0 {
		certTTL = defaultCertTTL
	}

	issuer, err := newCertIssuer(cfg.Issuer, keyCfg, certTTL, logger)
	if err != nil {
		return nil, err
	}

	cache, err := lru.New[string, *tls.Certificate](maxCachedCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate cache: %w", err)
	}

	return &CertAutomation{
		issuer: issuer,
		logger: logger,
		cache:  cache,
	}, nil
}

func (c *CertAutomation) Run(ctx context.Context) {
	c.issuer.run(ctx)

	// When the issuer can rotate its CA, drop the cached certificates as soon as
	// it does rather than serving ones that no longer chain to it.
	if issuer, ok := c.issuer.(rotatableIssuer); ok {
		go c.purgeOnRotation(ctx, issuer.rotated())
	}
}

func (c *CertAutomation) GetCertificateForHost(ctx context.Context, host string, aliases ...string) (*tls.Certificate, error) {
	names := certNames(host, aliases)
	key := strings.Join(names, ",")

	if cert, ok := c.cachedCert(key); ok {
		return cert, nil
	}

	c.mu.Lock()
	rotations := c.caRotations
	c.mu.Unlock()

	// Sign outside the lock so a slow CA cannot stall handshakes for names that are already
	// cached. A burst against a cold cache may sign the same names twice, which is cheaper.
	cert, err := c.issuer.issue(ctx, names)
	if err != nil {
		return nil, err
	}

	c.logger.Debug("Issued downstream certificate",
		zap.Strings("hosts", names),
		zap.Time("not_after", cert.Leaf.NotAfter),
	)

	c.mu.Lock()
	defer c.mu.Unlock()

	// The CA rotated while this certificate was in flight: serve it to this handshake
	// only, so the cache never holds a certificate from a previous CA.
	if rotations == c.caRotations {
		c.cache.Add(key, cert)
	}

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

// purgeOnRotation drops every cached certificate and counts the rotation, so an
// issuance already in flight cannot put a certificate from the previous CA back in the cache.
func (c *CertAutomation) purgeOnRotation(ctx context.Context, rotated <-chan struct{}) {
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

// cachedCert returns the cached certificate for the given name set while it is
// short of renewFraction of its lifetime. The lifetime is read off the
// certificate itself, since an issuer may hand back a shorter one than asked for.
func (c *CertAutomation) cachedCert(key string) (*tls.Certificate, bool) {
	cert, ok := c.cache.Get(key)
	if !ok {
		return nil, false
	}

	lifetime := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)
	renewAfter := cert.Leaf.NotBefore.Add(time.Duration(float64(lifetime) * renewFraction))

	return cert, time.Now().Before(renewAfter)
}
