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
	"strconv"
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

	// Each entry costs a renewal goroutine and a recurring CA request, so a Gateway serving many
	// resources needs a ceiling on the cache.
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

// hostCertManager holds the host certificates the Gateway presents to SSH clients, each signed
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
	key := hostCertCacheKey(principals)
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
	ticker := time.NewTicker(c.ttl)
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

// evictUnused drops the certificates not served for a full certificate lifetime, so a name the
// Gateway stops seeing does not keep renewing for the rest of the process's life. Sweeping once a
// lifetime leaves a certificate cached for between one and two lifetimes after its last use,
// depending on where that use falls between two sweeps.
func (c *hostCertManager) evictUnused(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, cert := range c.certByPrincipals {
		if now.Sub(cert.lastUsed) > c.ttl {
			cert.cancelRenewal()
			delete(c.certByPrincipals, key)
		}
	}
}

// evictOldest drops the least recently served certificate to make room for a new one. The caller
// holds c.mu and has checked that the cache is not empty.
func (c *hostCertManager) evictOldest() {
	var (
		oldestKey      string
		oldestLastUsed time.Time
	)

	for key, cert := range c.certByPrincipals {
		if oldestLastUsed.IsZero() || cert.lastUsed.Before(oldestLastUsed) {
			oldestKey, oldestLastUsed = key, cert.lastUsed
		}
	}

	c.certByPrincipals[oldestKey].cancelRenewal()
	delete(c.certByPrincipals, oldestKey)
}

// hostCertPrincipals returns the names a client may have used to reach the resource it asked for:
// the host from its CONNECT request, plus the resource's aliases. An older client translates an
// alias to the resource address before connecting, so the host it asks for is the address while the
// name it verifies the certificate against is still the alias.
//
// Principals are lowercased because OpenSSH matches them case-insensitively, and sorted so that the
// same set always yields the same slice.
func hostCertPrincipals(host string, aliases []string) []string {
	principals := map[string]struct{}{}

	for _, candidate := range slices.Concat([]string{host}, aliases) {
		principals[strings.ToLower(candidate)] = struct{}{}
	}

	return slices.Sorted(maps.Keys(principals))
}

func hostCertCacheKey(principals []string) string {
	encoded := make([]string, 0, len(principals))

	for _, principal := range principals {
		encoded = append(encoded, strconv.Itoa(len(principal))+":"+principal)
	}

	return strings.Join(encoded, ",")
}

// autoRenewingCertSigner presents a certificate that it re-signs before it expires and after each
// CA key rotation.
type autoRenewingCertSigner struct {
	ca        ca
	rotated   <-chan struct{} // Closed at the next CA key rotation; nil for a CA that cannot rotate
	certReq   *certificateRequest
	keySigner ssh.Signer
	logger    *zap.Logger

	mu         sync.RWMutex
	certSigner ssh.Signer
	renewAt    time.Time // Zero when the certificate never needs renewing
	expiresAt  time.Time // Zero when the certificate never expires
}

func newAutoRenewingCertSigner(ctx context.Context, ca ca, certReq *certificateRequest, keySigner ssh.Signer, logger *zap.Logger) (*autoRenewingCertSigner, error) {
	certSigner := &autoRenewingCertSigner{
		ca:        ca,
		certReq:   certReq,
		keySigner: keySigner,
		logger:    logger,
	}

	// Fetch the rotation channel before signing, not after: a key that rotates while the CA is
	// signing then closes this channel, so the certificate it returns is re-signed as soon as the
	// renewal loop starts instead of surviving until its renewal time.
	certSigner.fetchRotationChannel()

	if _, err := certSigner.updateCertSigner(ctx); err != nil {
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

// fetchRotationChannel makes s wait on the CA's current rotation channel. An open channel is
// always the current one, because a rotation replaces the channel only by closing it; so this
// runs where a channel goes stale: at construction (none held yet) and after consuming a close.
func (s *autoRenewingCertSigner) fetchRotationChannel() {
	if rotatable, ok := s.ca.(rotatableCA); ok {
		s.rotated = rotatable.rotated()
	}
}

// renewalLoop re-signs the certificate once it is renewFraction into its lifetime or as soon as the
// CA key rotates, retrying every retryInterval while the CA fails.
func (s *autoRenewingCertSigner) renewalLoop(ctx context.Context) {
	s.mu.RLock()
	nextRenewal := s.renewAt
	s.mu.RUnlock()

	if nextRenewal.IsZero() {
		return
	}

	timer := time.NewTimer(time.Until(nextRenewal))
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
		case <-s.rotated:
			// The close consumed here retired the channel, so fetch the one the rotation installed.
			s.fetchRotationChannel()
		case <-ctx.Done():
			return
		}

		nextRenewal, err := s.updateCertSigner(ctx)
		if err != nil {
			s.mu.RLock()
			expiresAt := s.expiresAt
			s.mu.RUnlock()

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
