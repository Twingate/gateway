// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

var errHostCertExpired = errors.New("the Gateway's host certificate expired and the CA has not renewed it")

const (
	retryInterval = 10 * time.Second
	renewFraction = 0.80 // renew certificate when 80% into lifetime

	// maxCachedHostCerts bounds the certificates a resource with a wildcard address can accumulate:
	// every hostname under the wildcard is a distinct principal set, and the Gateway signs one
	// before it has dialed the upstream, so an unbounded cache would let a client mint CA requests
	// and renewal goroutines for hostnames that resolve to nothing.
	maxCachedHostCerts = 1024
)

type certType uint32

const (
	HostCert certType = ssh.HostCert
	UserCert certType = ssh.UserCert
)

const (
	userString = "user"
	hostString = "host"
)

func (ct certType) String() string {
	switch ct {
	case UserCert:
		return userString
	case HostCert:
		return hostString
	default:
		return ""
	}
}

type certificateRequest struct {
	certType    certType
	publicKey   ssh.PublicKey
	principals  []string
	ttl         time.Duration   // Requested validity (CA may shorten)
	permissions ssh.Permissions // For user certs
}

// hostCertManager holds the host certificates the Gateway presents to protocol clients, each signed
// for the names a client may have used to reach a resource and keyed by those names. Each cached
// certificate keeps itself signed by the CA's current key in the background.
type hostCertManager struct {
	ca        ca
	publicKey ssh.PublicKey
	keySigner ssh.Signer
	ttl       time.Duration
	maxCerts  int
	logger    *zap.Logger

	mu               sync.Mutex
	certByPrincipals map[string]cachedHostCert
}

type cachedHostCert struct {
	signer        *autoRenewingCertSigner
	cancelRenewal context.CancelFunc
	lastUsed      time.Time
}

func newHostCertManager(ca ca, publicKey ssh.PublicKey, keySigner ssh.Signer, ttl time.Duration, logger *zap.Logger) *hostCertManager {
	return &hostCertManager{
		ca:               ca,
		publicKey:        publicKey,
		keySigner:        keySigner,
		ttl:              ttl,
		maxCerts:         maxCachedHostCerts,
		logger:           logger,
		certByPrincipals: map[string]cachedHostCert{},
	}
}

// signer returns the signer for the host certificate to present to a client that asked for host,
// signing a new certificate when the cache holds none for host and aliases together.
func (c *hostCertManager) signer(ctx context.Context, host string, aliases []string) (ssh.Signer, error) {
	principals := hostCertPrincipals(host, aliases)
	key := strings.Join(principals, ",")
	now := time.Now()

	c.mu.Lock()

	if cert, cached := c.certByPrincipals[key]; cached {
		cert.lastUsed = now
		c.certByPrincipals[key] = cert
		c.mu.Unlock()

		// Renewal has been failing for the last fifth of the certificate's lifetime to get here,
		// so signing a new one would wait on a CA that is already known to be down.
		if !cert.signer.validAt(now) {
			return nil, fmt.Errorf("%w: principals %v", errHostCertExpired, principals)
		}

		return cert.signer, nil
	}
	c.mu.Unlock()

	// Sign outside the lock so a slow CA cannot stall handshakes for principals that are already
	// cached. A burst against a cold cache may sign the same principals twice, which is cheaper.
	certSigner, err := newAutoRenewingCertSigner(ctx, c.ca, &certificateRequest{
		certType:   HostCert,
		publicKey:  c.publicKey,
		principals: principals,
		ttl:        c.ttl,
	}, c.keySigner, c.logger)
	if err != nil {
		return nil, err
	}

	// Renewal outlives the call that signed the certificate, so it runs for as long as the cache
	// holds the certificate rather than on the caller's context.
	// #nosec G118 -- the cached certificate owns cancelRenewal and calls it when it is replaced or evicted
	renewalCtx, cancelRenewal := context.WithCancel(context.WithoutCancel(ctx))

	c.mu.Lock()
	defer c.mu.Unlock()

	if replaced, ok := c.certByPrincipals[key]; ok {
		replaced.cancelRenewal()
	} else if len(c.certByPrincipals) >= c.maxCerts {
		c.evictOldest()
	}

	go certSigner.renewalLoop(renewalCtx)

	c.certByPrincipals[key] = cachedHostCert{
		signer:        certSigner,
		cancelRenewal: cancelRenewal,
		lastUsed:      now,
	}

	return certSigner, nil
}

func (c *hostCertManager) start(ctx context.Context) {
	go c.maintenanceLoop(ctx)
}

// maintenanceLoop runs until ctx is canceled. Keeping a certificate signed by the CA's current key
// belongs to each cached certificate, not here.
func (c *hostCertManager) maintenanceLoop(ctx context.Context) {
	// Sweeping twice per lifetime keeps a certificate that was last used just after a sweep from
	// renewing for another full lifetime before the next one sees it.
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.evictAll()

			return
		case <-ticker.C:
			c.evictUnused(time.Now())
		}
	}
}

func (c *hostCertManager) evictAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, cert := range c.certByPrincipals {
		cert.cancelRenewal()
	}

	clear(c.certByPrincipals)
}

// evictUnused drops the certificates not served for a full certificate lifetime, so that names the
// Gateway no longer sees stop renewing for the lifetime of the process. A certificate lives for
// between one and one and a half lifetimes after its last use, depending on where that use falls
// between two sweeps.
func (c *hostCertManager) evictUnused(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for principals, cert := range c.certByPrincipals {
		if now.Sub(cert.lastUsed) > c.ttl {
			cert.cancelRenewal()
			delete(c.certByPrincipals, principals)
		}
	}
}

// evictOldest drops the least recently served certificate to make room for a new one. The caller
// holds c.mu and has checked that the cache is not empty.
func (c *hostCertManager) evictOldest() {
	var (
		oldest         string
		oldestLastUsed time.Time
	)

	for principals, cert := range c.certByPrincipals {
		if oldestLastUsed.IsZero() || cert.lastUsed.Before(oldestLastUsed) {
			oldest, oldestLastUsed = principals, cert.lastUsed
		}
	}

	c.certByPrincipals[oldest].cancelRenewal()
	delete(c.certByPrincipals, oldest)
}

// hostCertPrincipals returns the names a client may have used to reach the resource it asked for:
// the host from its CONNECT request, plus the resource's aliases because a client that resolves an
// alias to the resource address itself still verifies the certificate against the alias. The
// resource address is deliberately absent, since it may be a pattern such as *.example.com that no
// client matches consistently. Names are lowercased because OpenSSH matches principals
// case-insensitively, and sorted so that the same set always yields the same slice.
func hostCertPrincipals(host string, aliases []string) []string {
	unique := map[string]struct{}{}

	for _, candidate := range slices.Concat([]string{host}, aliases) {
		unique[strings.ToLower(candidate)] = struct{}{}
	}

	return slices.Sorted(maps.Keys(unique))
}

// autoRenewingCertSigner presents a certificate that it re-signs before it expires and after each
// CA key rotation, so a handshake never waits on the CA and never gets a certificate signed by a
// key clients have stopped trusting.
type autoRenewingCertSigner struct {
	ca          ca
	rotated     <-chan struct{} // Nil for a CA whose key cannot rotate during the process lifetime
	unsubscribe func()
	certReq     *certificateRequest
	keySigner   ssh.Signer
	logger      *zap.Logger

	mu         sync.RWMutex
	certSigner ssh.Signer
	renewAt    time.Time // Zero when the certificate never needs renewing
	expiresAt  time.Time // Zero when the certificate never expires
}

func newAutoRenewingCertSigner(ctx context.Context, ca ca, certReq *certificateRequest, keySigner ssh.Signer, logger *zap.Logger) (*autoRenewingCertSigner, error) {
	certSigner := &autoRenewingCertSigner{
		ca:          ca,
		unsubscribe: func() {},
		certReq:     certReq,
		keySigner:   keySigner,
		logger:      logger,
	}

	// Subscribe before signing, not after: a key that rotates while the CA is signing then leaves a
	// notification waiting, so the certificate it returns is re-signed as soon as the renewal loop
	// starts instead of surviving until its renewal time.
	if rotatable, ok := ca.(rotatableCA); ok {
		certSigner.rotated, certSigner.unsubscribe = rotatable.subscribeRotation()
	}

	if _, err := certSigner.updateCertSigner(ctx); err != nil {
		// No renewal loop will run for this signer, so nothing else would end the subscription.
		certSigner.unsubscribe()

		return nil, err
	}

	return certSigner, nil
}

func (s *autoRenewingCertSigner) PublicKey() ssh.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.certSigner.PublicKey()
}

func (s *autoRenewingCertSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	s.mu.RLock()
	certSigner := s.certSigner
	s.mu.RUnlock()

	return certSigner.Sign(rand, data)
}

func (s *autoRenewingCertSigner) validAt(t time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.expiresAt.IsZero() || t.Before(s.expiresAt)
}

// renewalLoop re-signs the certificate once it is renewFraction into its lifetime or as soon as the
// CA key rotates, retrying every retryInterval while the CA fails.
func (s *autoRenewingCertSigner) renewalLoop(ctx context.Context) {
	defer s.unsubscribe()

	s.mu.RLock()
	nextRenewal := s.renewAt
	s.mu.RUnlock()

	if nextRenewal.IsZero() {
		return
	}

	rotated := s.rotated

	timer := time.NewTimer(time.Until(nextRenewal))
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
		case _, rotating := <-rotated:
			if !rotating {
				rotated = nil // The CA key can no longer rotate, so stop waiting on it

				continue
			}
		case <-ctx.Done():
			return
		}

		nextRenewal, err := s.updateCertSigner(ctx)
		if err != nil {
			s.mu.RLock()
			expiresAt := s.expiresAt
			s.mu.RUnlock()

			// expires_at is how long the CA has to recover before connections start failing.
			s.logger.Error("Failed to renew the Gateway's certificate",
				zap.String("cert_type", s.certReq.certType.String()),
				zap.Strings("principals", s.certReq.principals),
				zap.Time("expires_at", expiresAt),
				zap.Error(err))

			timer.Reset(retryInterval)

			continue
		}

		if nextRenewal.IsZero() {
			return
		}

		timer.Reset(time.Until(nextRenewal))
	}
}

func (s *autoRenewingCertSigner) updateCertSigner(ctx context.Context) (time.Time, error) {
	cert, err := s.ca.sign(ctx, s.certReq)
	if err != nil {
		return time.Time{}, err
	}

	certSigner, err := ssh.NewCertSigner(cert, s.keySigner)
	if err != nil {
		return time.Time{}, err
	}

	renewAt := renewTime(cert)

	var expiresAt time.Time
	if cert.ValidBefore <= uint64(math.MaxInt64) {
		expiresAt = time.Unix(int64(cert.ValidBefore), 0)
	}

	s.mu.Lock()
	s.certSigner = certSigner
	s.renewAt = renewAt
	s.expiresAt = expiresAt
	s.mu.Unlock()

	return renewAt, nil
}

func renewTime(cert *ssh.Certificate) time.Time {
	if cert.ValidAfter > uint64(math.MaxInt64) {
		return time.Time{} // timestamp too far in future, don't renew
	}

	if cert.ValidBefore > uint64(math.MaxInt64) {
		return time.Time{} // expiry too far in future, don't renew
	}

	issuedAt := time.Unix(int64(cert.ValidAfter), 0)
	expiresAt := time.Unix(int64(cert.ValidBefore), 0)
	lifetime := expiresAt.Sub(issuedAt)

	return issuedAt.Add(time.Duration(float64(lifetime) * renewFraction))
}
