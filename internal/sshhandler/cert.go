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
	renewCh   <-chan struct{} // Signals an immediate re-sign after a CA key reload
	logger    *zap.Logger

	mu         sync.RWMutex
	certSigner ssh.Signer
}

func newAutoRenewingCertSigner(ctx context.Context, ca ca, certReq *certificateRequest, keySigner ssh.Signer, renewCh <-chan struct{}, logger *zap.Logger) (*autoRenewingCertSigner, error) {
	certSigner := &autoRenewingCertSigner{
		ca:        ca,
		certReq:   certReq,
		keySigner: keySigner,
		renewCh:   renewCh,
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

	timer := time.NewTimer(time.Until(nextRenewal))
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
		case <-s.renewCh:
			s.logger.Info("CA key reloaded, re-signing certificate", zap.String("cert_type", s.certReq.certType.String()))
		case <-ctx.Done():
			return ctx.Err()
		}

		nextRenewal, err := s.updateCertSigner(ctx)
		if err != nil {
			timer.Reset(retryInterval)

			continue
		}

		if nextRenewal.IsZero() {
			return nil
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
	expiresAt := time.Unix(int64(cert.ValidBefore), 0)
	lifetime := expiresAt.Sub(issuedAt)

	return issuedAt.Add(time.Duration(float64(lifetime) * renewFraction))
}
