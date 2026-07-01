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

		s, err := newAutoRenewingCertSigner(ctx, ca, req, keySigner, logger)
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

		s, err := newAutoRenewingCertSigner(ctx, ca, req, keySigner, logger)
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

		require.ErrorIs(t, <-errCh, context.Canceled)
	})
}

func TestAutoRenewingCertSigner_FloorsRenewalWhenRenewTimeInPast(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logger := zap.NewNop()

		keySigner, _, err := keyConfig{}.Generate(rand.Reader)
		require.NoError(t, err)

		caSigner, _, err := keyConfig{}.Generate(rand.Reader)
		require.NoError(t, err)

		ca := &stubCA{signer: caSigner, errOnCalls: map[int]error{}}

		// A negative TTL yields an already-expired cert, so renewTime lands in the past.
		// The loop must fall back to retryInterval rather than re-signing in a tight loop.
		req := &certificateRequest{
			certType:  ssh.HostCert,
			publicKey: keySigner.PublicKey(),
			ttl:       -time.Hour,
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		s, err := newAutoRenewingCertSigner(ctx, ca, req, keySigner, logger)
		require.NoError(t, err)

		errCh := make(chan error, 1)

		go func() {
			errCh <- s.renewalLoop(ctx)
		}()

		synctest.Wait()
		require.Equal(t, 1, ca.calls(), "initial sign calls")

		time.Sleep(retryInterval - 1*time.Second)
		synctest.Wait()
		require.Equal(t, 1, ca.calls(), "before floored renewal sign calls")

		time.Sleep(1 * time.Second)
		synctest.Wait()
		require.Equal(t, 2, ca.calls(), "after floored renewal sign calls")

		cancel()
		synctest.Wait()

		require.ErrorIs(t, <-errCh, context.Canceled)
	})
}

func TestRenewTime(t *testing.T) {
	tests := []struct {
		name              string
		validAfterOffset  time.Duration
		validBeforeOffset time.Duration
		wantOffset        time.Duration
	}{
		{
			name:              "renews at fraction of lifetime",
			validAfterOffset:  0,
			validBeforeOffset: 100 * time.Minute,
			wantOffset:        80 * time.Minute,
		},
		{
			// A backdated start must not drag the schedule earlier: the cert was just
			// issued, so renewal is measured from now, not from ValidAfter.
			name:              "backdated start schedules from now",
			validAfterOffset:  -time.Hour,
			validBeforeOffset: 100 * time.Minute,
			wantOffset:        80 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			cert := &ssh.Certificate{
				ValidAfter:  mustUint64(now.Add(tt.validAfterOffset)),
				ValidBefore: mustUint64(now.Add(tt.validBeforeOffset)),
			}

			require.WithinDuration(t, now.Add(tt.wantOffset), renewTime(cert), 2*time.Second)
		})
	}
}

func TestRenewTime_Infinity(t *testing.T) {
	cert := &ssh.Certificate{ValidBefore: ssh.CertTimeInfinity}
	require.True(t, renewTime(cert).IsZero())
}
