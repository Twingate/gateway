// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type stubCA struct {
	mu         sync.Mutex
	signer     ssh.Signer
	signCalls  int
	errOnCalls map[int]error
}

func (c *stubCA) publicKey(_ context.Context) (ssh.PublicKey, error) {
	return c.signer.PublicKey(), nil
}

func (c *stubCA) sign(_ context.Context, req *certificateRequest) (*ssh.Certificate, error) {
	c.mu.Lock()
	c.signCalls++
	err := c.errOnCalls[c.signCalls]
	c.mu.Unlock()

	if err != nil {
		return nil, err
	}

	// Align to whole seconds because ssh.Certificate uses second-level granularity.
	now := time.Now().Truncate(time.Second)

	cert := &ssh.Certificate{
		Key:         req.publicKey,
		CertType:    uint32(req.certType),
		ValidAfter:  mustUint64(now),                 // #nosec G115 -- time.Now() is always positive
		ValidBefore: uint64(now.Add(req.ttl).Unix()), // #nosec G115 -- time.Now() is always positive
	}

	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		return nil, err
	}

	return cert, nil
}

func (c *stubCA) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.signCalls
}

func TestAutoRenewingCertSigner_RenewsAtExpectedTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logger := zap.NewNop()

		// Certified key
		keySigner, _, err := keyConfig{}.Generate(rand.Reader)
		require.NoError(t, err)

		// CA
		caSigner, _, err := keyConfig{}.Generate(rand.Reader)
		require.NoError(t, err)

		ca := &stubCA{signer: caSigner, errOnCalls: map[int]error{}}

		req := &certificateRequest{
			certType:  ssh.HostCert,
			publicKey: keySigner.PublicKey(),
			ttl:       100 * time.Minute,
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		s, err := newAutoRenewingCertSigner(ctx, ca, req, keySigner, nil, logger)
		require.NoError(t, err)
		require.NotNil(t, s.PublicKey())
		require.IsType(t, &ssh.Certificate{}, s.PublicKey())

		data := []byte("hello")
		sig, err := s.Sign(rand.Reader, data)
		require.NoError(t, err)
		require.NotNil(t, sig)
		require.NoError(t, s.PublicKey().Verify(data, sig))

		errCh := make(chan error, 1)

		go func() {
			errCh <- s.renewalLoop(ctx)
		}()

		// Ensure renewal goroutine is blocked on the first timer.
		synctest.Wait()
		require.Equal(t, 1, ca.calls(), "initial sign calls")

		// renewFraction=0.8, ttl=100m => renewal at +80m.
		time.Sleep(80*time.Minute - 1*time.Second)
		synctest.Wait()
		require.Equal(t, 1, ca.calls(), "before renewal sign calls")

		time.Sleep(1 * time.Second)
		synctest.Wait()
		require.Equal(t, 2, ca.calls(), "after renewal sign calls")

		// Stop renewal loop.
		cancel()
		synctest.Wait()

		err = <-errCh
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestAutoRenewingCertSigner_RetriesOnRenewError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logger := zap.NewNop()

		keySigner, _, err := keyConfig{}.Generate(rand.Reader)
		require.NoError(t, err)

		caSigner, _, err := keyConfig{}.Generate(rand.Reader)
		require.NoError(t, err)

		// Fail the first renewal attempt (call #2), succeed on retry (call #3).
		ca := &stubCA{signer: caSigner, errOnCalls: map[int]error{2: errors.New("sign failed")}}

		req := &certificateRequest{
			certType:  ssh.HostCert,
			publicKey: keySigner.PublicKey(),
			ttl:       100 * time.Minute,
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		s, err := newAutoRenewingCertSigner(ctx, ca, req, keySigner, nil, logger)
		require.NoError(t, err)

		errCh := make(chan error, 1)

		go func() {
			errCh <- s.renewalLoop(ctx)
		}()

		synctest.Wait()
		require.Equal(t, 1, ca.calls(), "initial sign calls")

		// Advance to the renewal time (+80m): renewal attempt should happen and fail.
		time.Sleep(80 * time.Minute)
		synctest.Wait()
		require.Equal(t, 2, ca.calls(), "after failed renewal attempt sign calls")

		// Retry interval is 10s.
		time.Sleep(10 * time.Second)
		synctest.Wait()
		require.Equal(t, 3, ca.calls(), "after retry sign calls")

		cancel()
		synctest.Wait()

		<-errCh
	})
}

func TestAutoRenewingCertSigner_ResignsOnCAKeyRotation(t *testing.T) {
	keyPEM, oldPublicKey := generateCAKey(t)
	keyFile := createCAKeyFile(t, keyPEM)

	keyReloader := newKeyReloader(keyFile, zap.NewNop())
	require.NoError(t, keyReloader.load())

	keySigner, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	req := &certificateRequest{
		certType:  ssh.HostCert,
		publicKey: keySigner.PublicKey(),
		ttl:       24 * time.Hour,
	}

	ca := &embeddedCA{
		getSigner: keyReloader.getSigner,
	}

	s, err := newAutoRenewingCertSigner(t.Context(), ca, req, keySigner, keyReloader.reloadCh, zap.NewNop())
	require.NoError(t, err)

	go func() {
		_ = s.renewalLoop(t.Context())
	}()

	keyReloader.Run(t.Context())

	cert, ok := s.PublicKey().(*ssh.Certificate)
	require.True(t, ok)
	require.Equal(t, oldPublicKey.Marshal(), cert.SignatureKey.Marshal())

	newKeyPEM, newPublicKey := generateCAKey(t)
	replaceCAKeyFile(t, keyFile, newKeyPEM)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		cert, ok := s.PublicKey().(*ssh.Certificate)
		require.True(c, ok)

		require.Equal(c, newPublicKey.Marshal(), cert.SignatureKey.Marshal())
	}, time.Second, 5*time.Millisecond, "host certificate was not re-signed after CA key rotation")
}

func TestRenewTime(t *testing.T) {
	cert := &ssh.Certificate{
		ValidAfter:  0,
		ValidBefore: 100,
	}

	got := renewTime(cert)
	want := time.Unix(80, 0)
	require.Equal(t, want, got)
}

func TestRenewTime_Infinity(t *testing.T) {
	cert := &ssh.Certificate{ValidBefore: ssh.CertTimeInfinity}
	require.True(t, renewTime(cert).IsZero())
}
