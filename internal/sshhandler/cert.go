// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"io"
	"math"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	retryInterval = 10 * time.Second
	renewFraction = 0.80 // renew certificate when 80% into lifetime
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

type autoRenewingCertSigner struct {
	ca        ca
	certReq   *certificateRequest
	keySigner ssh.Signer
	logger    *zap.Logger

	mu         sync.RWMutex
	certSigner ssh.Signer
}

func newAutoRenewingCertSigner(ctx context.Context, ca ca, certReq *certificateRequest, keySigner ssh.Signer, logger *zap.Logger) (*autoRenewingCertSigner, error) {
	certSigner := &autoRenewingCertSigner{
		ca:        ca,
		certReq:   certReq,
		keySigner: keySigner,
		logger:    logger,
	}

	_, err := certSigner.updateCertSigner(ctx)
	if err != nil {
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

func (s *autoRenewingCertSigner) renewalLoop(ctx context.Context) error {
	s.mu.RLock()
	certSigner := s.certSigner
	s.mu.RUnlock()

	cert := certSigner.PublicKey().(*ssh.Certificate) //revive:disable:unchecked-type-assertion -- certSigner always wraps a certificate

	nextRenewal := renewTime(cert)
	if nextRenewal.IsZero() {
		return nil
	}

	timer := time.NewTimer(s.renewalDelay(nextRenewal))
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			nextRenewal, err := s.updateCertSigner(ctx)
			if err != nil {
				timer.Reset(retryInterval)

				break
			}

			if nextRenewal.IsZero() {
				return nil
			}

			timer.Reset(s.renewalDelay(nextRenewal))
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// renewalDelay returns the delay until t, floored at retryInterval so an imminent or past renewal
// time cannot busy-loop the timer. Hitting the floor means the renewal point falls within
// retryInterval, i.e. the CA issued a very short-lived or backdated cert, so it warns to surface it.
func (s *autoRenewingCertSigner) renewalDelay(t time.Time) time.Duration {
	if d := time.Until(t); d >= retryInterval {
		return d
	}

	s.logger.Warn(
		"certificate renewal due within the retry interval; the CA may be issuing short-lived or backdated certificates",
		zap.String("certType", s.certReq.certType.String()),
		zap.Duration("requestedTTL", s.certReq.ttl),
		zap.Time("renewAt", t),
	)

	return retryInterval
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

	s.mu.Lock()
	s.certSigner = certSigner
	s.mu.Unlock()

	return renewTime(cert), nil
}

func renewTime(cert *ssh.Certificate) time.Time {
	if cert.ValidAfter > uint64(math.MaxInt64) {
		return time.Time{} // timestamp too far in future, don't renew
	}

	if cert.ValidBefore > uint64(math.MaxInt64) {
		return time.Time{} // expiry too far in future, don't renew
	}

	issuedAt := time.Unix(int64(cert.ValidAfter), 0)
	if now := time.Now(); issuedAt.Before(now) {
		// The cert was just issued, so schedule from now rather than a backdated start.
		issuedAt = now
	}

	expiresAt := time.Unix(int64(cert.ValidBefore), 0)
	lifetime := expiresAt.Sub(issuedAt)

	return issuedAt.Add(time.Duration(float64(lifetime) * renewFraction))
}
