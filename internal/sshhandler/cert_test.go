// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"crypto/rand"
	"errors"
	"maps"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

var errSignFailed = errors.New("sign failed")

type stubCA struct {
	rotationNotifier

	// onSign runs once the signing key is captured, so a test can rotate the key mid-signature.
	onSign func()

	mu        sync.Mutex
	signer    ssh.Signer
	signCalls int
	errFrom   int // Fail every call from this one on; zero to fail none
}

func (c *stubCA) publicKey(_ context.Context) (ssh.PublicKey, error) {
	return c.signer.PublicKey(), nil
}

func (c *stubCA) sign(_ context.Context, req *certificateRequest) (*ssh.Certificate, error) {
	c.mu.Lock()
	c.signCalls++
	signer := c.signer
	failed := c.errFrom > 0 && c.signCalls >= c.errFrom
	c.mu.Unlock()

	if c.onSign != nil {
		c.onSign()
	}

	if failed {
		return nil, errSignFailed
	}

	// Align to whole seconds because ssh.Certificate uses second-level granularity.
	now := time.Now().Truncate(time.Second)

	cert := &ssh.Certificate{
		Key:             req.publicKey,
		CertType:        uint32(req.certType),
		ValidPrincipals: req.principals,
		ValidAfter:      mustUint64(now),                 // #nosec G115 -- time.Now() is always positive
		ValidBefore:     uint64(now.Add(req.ttl).Unix()), // #nosec G115 -- time.Now() is always positive
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}

	return cert, nil
}

// rotate swaps the key the stub signs with and announces it.
func (c *stubCA) rotate(t *testing.T) ssh.PublicKey {
	t.Helper()

	signer, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	c.mu.Lock()
	c.signer = signer
	c.mu.Unlock()

	c.notifyRotation()

	return signer.PublicKey()
}

func (c *stubCA) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.signCalls
}

func (c *stubCA) failFrom(call int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.errFrom = call
}

// testHostCertTTL matches the TTL the renewal assertions below are written against: with
// renewFraction=0.8 the certificate is due for renewal 80 minutes in.
const testHostCertTTL = 100 * time.Minute

func newTestHostCertManager(t *testing.T, authority ca) *hostCertManager {
	t.Helper()

	keySigner, publicKey, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	return newHostCertManager(authority, publicKey, keySigner, testHostCertTTL, zap.NewNop())
}

func cachedCerts(manager *hostCertManager) map[string]cachedHostCert {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	return maps.Clone(manager.certByPrincipals)
}

func newStubCA(t *testing.T) *stubCA {
	t.Helper()

	caSigner, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	return &stubCA{signer: caSigner}
}

// signedCert returns the certificate the signer presents as its public key.
func signedCert(t *testing.T, signer ssh.Signer) *ssh.Certificate {
	t.Helper()

	cert, ok := signer.PublicKey().(*ssh.Certificate)
	require.True(t, ok)

	return cert
}

func TestHostCertManager_SignsForTheRequestedHostAndAliases(t *testing.T) {
	ca := newStubCA(t)
	manager := newTestHostCertManager(t, ca)

	signer, err := manager.signer(t.Context(), "vm.corp.internal", []string{"vm.internal"})
	require.NoError(t, err)

	assert.Equal(t, []string{"vm.corp.internal", "vm.internal"}, signedCert(t, signer).ValidPrincipals)
}

func TestHostCertManager_ReusesCachedCertificate(t *testing.T) {
	ca := newStubCA(t)
	manager := newTestHostCertManager(t, ca)

	_, err := manager.signer(t.Context(), "vm.corp.internal", []string{"vm.internal", "vm"})
	require.NoError(t, err)

	_, err = manager.signer(t.Context(), "vm.corp.internal", []string{"vm", "vm.internal"})
	require.NoError(t, err)

	assert.Equal(t, 1, ca.calls())
}

func TestHostCertManager_ResignsAtRenewTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca := newStubCA(t)
		manager := newTestHostCertManager(t, ca)
		manager.start(t.Context())

		signer, err := manager.signer(t.Context(), "vm.corp.internal", nil)
		require.NoError(t, err)
		require.Equal(t, 1, ca.calls())

		original := signedCert(t, signer).Marshal()

		time.Sleep(80*time.Minute - time.Second)
		synctest.Wait()
		assert.Equal(t, 1, ca.calls(), "before renewal time")

		time.Sleep(time.Second)
		synctest.Wait()
		assert.Equal(t, 2, ca.calls(), "at renewal time, without a connection asking for the certificate")
		assert.NotEqual(t, original, signedCert(t, signer).Marshal(), "the signer should present the renewed certificate")
	})
}

func TestHostCertManager_ServesCurrentCertificateWhenSignFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca := newStubCA(t)
		manager := newTestHostCertManager(t, ca)
		manager.start(t.Context())

		signer, err := manager.signer(t.Context(), "vm.corp.internal", nil)
		require.NoError(t, err)

		original := signedCert(t, signer).Marshal()

		// Fail the renewal, and let the retry that follows succeed.
		ca.failFrom(2)

		time.Sleep(80 * time.Minute)
		synctest.Wait()
		require.Equal(t, 2, ca.calls())

		ca.failFrom(0)

		stale, err := manager.signer(t.Context(), "vm.corp.internal", nil)
		require.NoError(t, err, "a still-valid certificate should outlive a CA failure")
		assert.Equal(t, original, signedCert(t, stale).Marshal())
		assert.Equal(t, 2, ca.calls(), "a handshake should not wait on the CA to retry the renewal")

		time.Sleep(retryInterval)
		synctest.Wait()
		assert.Equal(t, 3, ca.calls(), "the renewal should be retried after retryInterval")
		assert.NotEqual(t, original, signedCert(t, signer).Marshal())
	})
}

func TestHostCertManager_ReturnsErrorWhenTheCAFails(t *testing.T) {
	ca := newStubCA(t)
	ca.failFrom(1)

	manager := newTestHostCertManager(t, ca)

	_, err := manager.signer(t.Context(), "vm.corp.internal", nil)
	require.ErrorIs(t, err, errSignFailed)
}

func TestHostCertManager_ReturnsErrorWhenTheCachedCertificateExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca := newStubCA(t)
		manager := newTestHostCertManager(t, ca)
		manager.start(t.Context())

		_, err := manager.signer(t.Context(), "vm.corp.internal", nil)
		require.NoError(t, err)

		// Every renewal from here on fails, so the cached certificate reaches its expiry.
		ca.failFrom(2)

		time.Sleep(testHostCertTTL + time.Second)
		synctest.Wait()

		renewals := ca.calls()

		_, err = manager.signer(t.Context(), "vm.corp.internal", nil)
		require.ErrorIs(t, err, errHostCertExpired, "an expired certificate must not be served")
		assert.Equal(t, renewals, ca.calls(), "a handshake should not wait on a CA that is already failing")

		time.Sleep(retryInterval)
		synctest.Wait()
		assert.Equal(t, renewals+1, ca.calls(), "the renewal should keep retrying after the certificate expired")
	})
}

func TestHostCertManager_EvictsUnusedCertificates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca := newStubCA(t)
		manager := newTestHostCertManager(t, ca)
		manager.start(t.Context())

		_, err := manager.signer(t.Context(), "old.corp.internal", nil)
		require.NoError(t, err)

		// The sweep a lifetime after the certificate was last served still finds it used within
		// one; the next sweep does not.
		cached := hostCertCacheKey([]string{"old.corp.internal"})

		time.Sleep(testHostCertTTL)
		synctest.Wait()
		assert.Contains(t, cachedCerts(manager), cached)

		time.Sleep(testHostCertTTL)
		synctest.Wait()
		assert.NotContains(t, cachedCerts(manager), cached)

		renewals := ca.calls()

		time.Sleep(testHostCertTTL)
		synctest.Wait()

		assert.Equal(t, renewals, ca.calls(), "an evicted certificate should stop being renewed")
	})
}

func TestHostCertManager_EvictsTheOldestCertificateWhenFull(t *testing.T) {
	ca := newStubCA(t)
	manager := newTestHostCertManager(t, ca)
	manager.maxCerts = 2

	for _, host := range []string{"one.corp.internal", "two.corp.internal"} {
		_, err := manager.signer(t.Context(), host, nil)
		require.NoError(t, err)
	}

	// Serving the first host again leaves the second as the least recently served.
	_, err := manager.signer(t.Context(), "one.corp.internal", nil)
	require.NoError(t, err)

	_, err = manager.signer(t.Context(), "three.corp.internal", nil)
	require.NoError(t, err)

	assert.ElementsMatch(t,
		[]string{hostCertCacheKey([]string{"one.corp.internal"}), hostCertCacheKey([]string{"three.corp.internal"})},
		slices.Collect(maps.Keys(cachedCerts(manager))))
}

func TestHostCertManager_ResignsAfterRotationDuringSigning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca := newStubCA(t)
		manager := newTestHostCertManager(t, ca)
		manager.start(t.Context())

		// The key rotates while the CA is signing, so the certificate that comes back already
		// carries the superseded key's signature by the time it reaches the cache.
		var rotatedKey ssh.PublicKey

		ca.onSign = sync.OnceFunc(func() { rotatedKey = ca.rotate(t) })

		signer, err := manager.signer(t.Context(), "vm.corp.internal", nil)
		require.NoError(t, err)

		synctest.Wait()

		assert.Equal(t, rotatedKey.Marshal(), signedCert(t, signer).SignatureKey.Marshal(),
			"the certificate should be re-signed without waiting for its renewal time")
	})
}

func TestHostCertManager_ConcurrentLookups(t *testing.T) {
	ca := newStubCA(t)
	manager := newTestHostCertManager(t, ca)

	hosts := []string{"one.corp.internal", "two.corp.internal", "three.corp.internal"}

	var wg sync.WaitGroup

	for range 10 {
		for _, host := range hosts {
			wg.Go(func() {
				_, err := manager.signer(t.Context(), host, nil)
				assert.NoError(t, err)
			})
		}
	}

	wg.Wait()

	assert.Len(t, cachedCerts(manager), len(hosts))
}

func TestHostCertPrincipals(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		aliases []string
		want    []string
	}{
		{
			name: "host only",
			host: "vm.corp.internal",
			want: []string{"vm.corp.internal"},
		},
		{
			name:    "host and aliases",
			host:    "vm.corp.internal",
			aliases: []string{"vm.internal", "vm"},
			want:    []string{"vm", "vm.corp.internal", "vm.internal"},
		},
		{
			name:    "lowercased and deduplicated",
			host:    "VM.corp.internal",
			aliases: []string{"vm.CORP.internal", "vm.internal"},
			want:    []string{"vm.corp.internal", "vm.internal"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, hostCertPrincipals(test.host, test.aliases))
		})
	}
}

func TestHostCertCacheKey(t *testing.T) {
	// A principal holding the delimiter must not collide with two principals.
	assert.NotEqual(t,
		hostCertCacheKey([]string{"one.corp.internal", "two.corp.internal"}),
		hostCertCacheKey([]string{"one.corp.internal,two.corp.internal"}))
}

func TestAutoRenewingCertSigner_ResignsOnCAKeyRotation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca := newStubCA(t)

		keySigner, publicKey, err := keyConfig{}.Generate(rand.Reader)
		require.NoError(t, err)

		signer, err := newAutoRenewingCertSigner(t.Context(), ca, &certificateRequest{
			certType:   HostCert,
			publicKey:  publicKey,
			principals: []string{"vm.corp.internal"},
			ttl:        testHostCertTTL,
		}, keySigner, zap.NewNop())
		require.NoError(t, err)

		go signer.renewalLoop(t.Context())

		rotatedKey := ca.rotate(t)

		synctest.Wait()

		assert.Equal(t, 2, ca.calls(), "the rotation should re-sign well before the renewal time")
		assert.Equal(t, rotatedKey.Marshal(), signedCert(t, signer).SignatureKey.Marshal())

		// The subscription keeps delivering: a second rotation re-signs again.
		rotatedAgain := ca.rotate(t)

		synctest.Wait()

		assert.Equal(t, 3, ca.calls())
		assert.Equal(t, rotatedAgain.Marshal(), signedCert(t, signer).SignatureKey.Marshal())
	})
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
