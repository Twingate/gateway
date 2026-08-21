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
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/ssh"
)

var errSignFailed = errors.New("sign failed")

type stubCA struct {
	rotationNotifier

	// onSign runs once the signing key is captured, so a test can rotate the key mid-signature.
	onSign func()

	mu         sync.Mutex
	signer     ssh.Signer
	signCalls  int
	errOnCalls map[int]error
	errFrom    int // Fail every call from this one on; zero to fail none
}

func (c *stubCA) publicKey(_ context.Context) (ssh.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.signer.PublicKey(), nil
}

func (c *stubCA) sign(_ context.Context, req *certificateRequest) (*ssh.Certificate, error) {
	c.mu.Lock()
	c.signCalls++
	signer := c.signer
	err := c.errOnCalls[c.signCalls]

	if err == nil && c.errFrom > 0 && c.signCalls >= c.errFrom {
		err = errSignFailed
	}
	c.mu.Unlock()

	if c.onSign != nil {
		c.onSign()
	}

	if err != nil {
		return nil, err
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

func (c *stubCA) subscriberCount() int {
	c.rotationNotifier.mu.Lock()
	defer c.rotationNotifier.mu.Unlock()

	return len(c.subscribers)
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

func newStubCA(t *testing.T, errOnCalls map[int]error) *stubCA {
	t.Helper()

	caSigner, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	return &stubCA{signer: caSigner, errOnCalls: errOnCalls}
}

// signedCert returns the certificate the signer presents as its public key.
func signedCert(t *testing.T, signer ssh.Signer) *ssh.Certificate {
	t.Helper()

	cert, ok := signer.PublicKey().(*ssh.Certificate)
	require.True(t, ok)

	return cert
}

func TestHostCertManager_SignsForTheRequestedHostAndAliases(t *testing.T) {
	ca := newStubCA(t, nil)
	manager := newTestHostCertManager(t, ca)

	signer, err := manager.signer(t.Context(), "vm.example.com", []string{"vm.int"})
	require.NoError(t, err)

	cert := signedCert(t, signer)
	assert.Equal(t, []string{"vm.example.com", "vm.int"}, cert.ValidPrincipals)
	assert.Equal(t, uint32(ssh.HostCert), cert.CertType)
}

func TestHostCertManager_ReusesCachedCertificate(t *testing.T) {
	ca := newStubCA(t, nil)
	manager := newTestHostCertManager(t, ca)

	first, err := manager.signer(t.Context(), "vm.example.com", []string{"vm.int", "vm"})
	require.NoError(t, err)

	second, err := manager.signer(t.Context(), "vm.example.com", []string{"vm", "vm.int"})
	require.NoError(t, err)

	assert.Equal(t, 1, ca.calls())
	assert.Equal(t, signedCert(t, first).Marshal(), signedCert(t, second).Marshal())
}

func TestHostCertManager_CachesEachRequestedHostSeparately(t *testing.T) {
	ca := newStubCA(t, nil)
	manager := newTestHostCertManager(t, ca)

	// Both hosts reach the Gateway through one resource addressed *.example.com, so neither
	// certificate may displace the other.
	first, err := manager.signer(t.Context(), "one.example.com", nil)
	require.NoError(t, err)

	second, err := manager.signer(t.Context(), "two.example.com", nil)
	require.NoError(t, err)

	assert.Equal(t, []string{"one.example.com"}, signedCert(t, first).ValidPrincipals)
	assert.Equal(t, []string{"two.example.com"}, signedCert(t, second).ValidPrincipals)
	assert.Len(t, cachedCerts(manager), 2)

	again, err := manager.signer(t.Context(), "one.example.com", nil)
	require.NoError(t, err)

	assert.Equal(t, 2, ca.calls())
	assert.Equal(t, signedCert(t, first).Marshal(), signedCert(t, again).Marshal())
}

func TestHostCertManager_KeepsPrincipalSetsWithASeparatorApart(t *testing.T) {
	ca := newStubCA(t, nil)
	manager := newTestHostCertManager(t, ca)

	// An alias reaches the principals without passing config.HostnameRegexp, so a name holding the
	// character that delimits a cache key must not merge two principal sets into one entry.
	separate, err := manager.signer(t.Context(), "one.example.com", []string{"two.example.com"})
	require.NoError(t, err)

	merged, err := manager.signer(t.Context(), "one.example.com,two.example.com", []string{"one.example.com,two.example.com"})
	require.NoError(t, err)

	assert.Equal(t, []string{"one.example.com", "two.example.com"}, signedCert(t, separate).ValidPrincipals)
	assert.Equal(t, []string{"one.example.com,two.example.com"}, signedCert(t, merged).ValidPrincipals)
	assert.Equal(t, 2, ca.calls())
	assert.Len(t, cachedCerts(manager), 2)
}

func TestHostCertManager_ResignsWhenAliasesChange(t *testing.T) {
	ca := newStubCA(t, nil)
	manager := newTestHostCertManager(t, ca)

	_, err := manager.signer(t.Context(), "vm.example.com", nil)
	require.NoError(t, err)

	signer, err := manager.signer(t.Context(), "vm.example.com", []string{"vm.int"})
	require.NoError(t, err)

	assert.Equal(t, 2, ca.calls())
	assert.Equal(t, []string{"vm.example.com", "vm.int"}, signedCert(t, signer).ValidPrincipals)
}

func TestHostCertManager_ResignsAtRenewTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		ca := newStubCA(t, nil)
		manager := newTestHostCertManager(t, ca)
		manager.start(ctx)

		signer, err := manager.signer(ctx, "vm.example.com", nil)
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
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		// Fail the renewal (call #2), succeed on the retry (call #3).
		ca := newStubCA(t, map[int]error{2: errSignFailed})
		manager := newTestHostCertManager(t, ca)
		manager.start(ctx)

		signer, err := manager.signer(ctx, "vm.example.com", nil)
		require.NoError(t, err)

		original := signedCert(t, signer).Marshal()

		time.Sleep(80 * time.Minute)
		synctest.Wait()
		require.Equal(t, 2, ca.calls())

		stale, err := manager.signer(ctx, "vm.example.com", nil)
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
	ca := newStubCA(t, map[int]error{1: errSignFailed})
	manager := newTestHostCertManager(t, ca)

	_, err := manager.signer(t.Context(), "vm.example.com", nil)
	require.ErrorIs(t, err, errSignFailed)
}

func TestHostCertManager_ReturnsErrorWhenTheCachedCertificateExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		ca := newStubCA(t, nil)
		manager := newTestHostCertManager(t, ca)
		manager.start(ctx)

		_, err := manager.signer(ctx, "vm.example.com", nil)
		require.NoError(t, err)

		// Every renewal from here on fails, so the cached certificate reaches its expiry.
		ca.failFrom(2)

		time.Sleep(testHostCertTTL + time.Second)
		synctest.Wait()

		renewals := ca.calls()

		_, err = manager.signer(ctx, "vm.example.com", nil)
		require.ErrorIs(t, err, errHostCertExpired, "an expired certificate must not be served")
		assert.Equal(t, renewals, ca.calls(), "a handshake should not wait on a CA that is already failing")

		ca.failFrom(0)

		time.Sleep(retryInterval)
		synctest.Wait()
		require.Equal(t, renewals+1, ca.calls(), "the renewal should keep retrying after the certificate expired")

		_, err = manager.signer(ctx, "vm.example.com", nil)
		require.NoError(t, err, "the host should be served again once the CA recovers")
		assert.Equal(t, renewals+1, ca.calls(), "the renewed certificate should be served from the cache")
	})
}

func TestHostCertManager_EvictsUnusedCertificates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		ca := newStubCA(t, nil)
		manager := newTestHostCertManager(t, ca)
		manager.start(ctx)

		_, err := manager.signer(ctx, "old.example.com", nil)
		require.NoError(t, err)

		// The sweep a lifetime after the certificate was last served still finds it used within
		// one; the next sweep does not.
		cached := hostCertCacheKey([]string{"old.example.com"})

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
	ca := newStubCA(t, nil)
	manager := newTestHostCertManager(t, ca)
	manager.maxCerts = 2

	for _, host := range []string{"one.example.com", "two.example.com"} {
		_, err := manager.signer(t.Context(), host, nil)
		require.NoError(t, err)
	}

	// Serving the first host again leaves the second as the least recently served.
	_, err := manager.signer(t.Context(), "one.example.com", nil)
	require.NoError(t, err)

	_, err = manager.signer(t.Context(), "three.example.com", nil)
	require.NoError(t, err)

	assert.ElementsMatch(t,
		[]string{hostCertCacheKey([]string{"one.example.com"}), hostCertCacheKey([]string{"three.example.com"})},
		slices.Collect(maps.Keys(cachedCerts(manager))))
}

func TestHostCertManager_ResignsOnCAKeyRotation(t *testing.T) {
	keyPEM, oldPublicKey := generateCAKey(t)
	keyFile := createCAKeyFile(t, keyPEM)

	core, logs := observer.New(zapcore.InfoLevel)

	provider, err := newManualCA(keyFile, zap.New(core))
	require.NoError(t, err)
	require.NoError(t, provider.Start(t.Context()))

	manager := newTestHostCertManager(t, provider.gatewayHostCA())
	manager.start(t.Context())

	signer, err := manager.signer(t.Context(), "vm.example.com", nil)
	require.NoError(t, err)
	require.Equal(t, oldPublicKey.Marshal(), signedCert(t, signer).SignatureKey.Marshal())

	// newManualCA loads the key without the file watcher, so signing does not prove the watch is in
	// place. A replacement written before it is loses its event, and the watch only restarts a
	// minute later.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotEmpty(c, logs.FilterMessage("Start watching CA private key file changes").All())
	}, time.Second, 5*time.Millisecond, "the CA key file watcher never started")

	newKeyPEM, newPublicKey := generateCAKey(t)
	replaceCAKeyFile(t, keyFile, newKeyPEM)

	// The cached certificate re-signs itself: no handshake is needed to notice the rotation.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		require.Equal(c, newPublicKey.Marshal(), signedCert(t, signer).SignatureKey.Marshal())
	}, time.Second, 5*time.Millisecond, "host certificate was not re-signed after CA key rotation")
}

func TestHostCertManager_ResignsAfterRotationDuringSigning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		ca := newStubCA(t, nil)
		manager := newTestHostCertManager(t, ca)
		manager.start(ctx)

		// The key rotates while the CA is signing, so the certificate that comes back already
		// carries the superseded key's signature by the time it reaches the cache.
		var rotatedKey ssh.PublicKey

		ca.onSign = sync.OnceFunc(func() { rotatedKey = ca.rotate(t) })

		signer, err := manager.signer(ctx, "vm.example.com", nil)
		require.NoError(t, err)

		synctest.Wait()

		assert.Equal(t, rotatedKey.Marshal(), signedCert(t, signer).SignatureKey.Marshal(),
			"the certificate should be re-signed without waiting for its renewal time")
	})
}

func TestHostCertManager_ConcurrentLookups(t *testing.T) {
	ca := newStubCA(t, nil)
	manager := newTestHostCertManager(t, ca)

	hosts := []string{"one.example.com", "two.example.com", "three.example.com"}

	lookups := make([]string, 0, 10*len(hosts))
	for range 10 {
		lookups = append(lookups, hosts...)
	}

	signers := make([]ssh.Signer, len(lookups))
	errs := make([]error, len(lookups))

	var wg sync.WaitGroup

	for i, host := range lookups {
		wg.Go(func() {
			signers[i], errs[i] = manager.signer(t.Context(), host, nil)
		})
	}

	wg.Wait()

	for i, host := range lookups {
		require.NoError(t, errs[i])
		assert.Equal(t, []string{host}, signedCert(t, signers[i]).ValidPrincipals)
	}

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
			host: "vm.example.com",
			want: []string{"vm.example.com"},
		},
		{
			name:    "host and aliases",
			host:    "vm.example.com",
			aliases: []string{"vm.int", "vm"},
			want:    []string{"vm", "vm.example.com", "vm.int"},
		},
		{
			name:    "aliases in a different order",
			host:    "vm.example.com",
			aliases: []string{"vm", "vm.int"},
			want:    []string{"vm", "vm.example.com", "vm.int"},
		},
		{
			name:    "lowercased and deduplicated",
			host:    "VM.example.com",
			aliases: []string{"vm.EXAMPLE.com", "vm.int"},
			want:    []string{"vm.example.com", "vm.int"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, hostCertPrincipals(test.host, test.aliases))
		})
	}
}

func newTestCertSigner(ctx context.Context, t *testing.T, authority ca, logger *zap.Logger) (*autoRenewingCertSigner, error) {
	t.Helper()

	keySigner, publicKey, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	return newAutoRenewingCertSigner(ctx, authority, &certificateRequest{
		certType:   HostCert,
		publicKey:  publicKey,
		principals: []string{"vm.example.com"},
		ttl:        testHostCertTTL,
	}, keySigner, logger)
}

func TestAutoRenewingCertSigner_ResignsOnCAKeyRotation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		ca := newStubCA(t, nil)

		signer, err := newTestCertSigner(ctx, t, ca, zap.NewNop())
		require.NoError(t, err)

		go signer.renewalLoop(ctx)

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

func TestAutoRenewingCertSigner_EndsSubscriptionWhenRenewalStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		ca := newStubCA(t, nil)

		signer, err := newTestCertSigner(ctx, t, ca, zap.NewNop())
		require.NoError(t, err)

		go signer.renewalLoop(ctx)

		synctest.Wait()
		require.Equal(t, 1, ca.subscriberCount())

		// Eviction, replacement and shutdown all cancel the renewal context, and the CA holds a
		// channel per subscription until the loop it belongs to gives it back.
		cancel()
		synctest.Wait()

		assert.Zero(t, ca.subscriberCount())
	})
}

func TestAutoRenewingCertSigner_EndsSubscriptionWhenTheFirstSignatureFails(t *testing.T) {
	ca := newStubCA(t, map[int]error{1: errSignFailed})

	// No renewal loop runs for a signer that never got a certificate, so the constructor is the
	// only thing that can give the subscription back.
	_, err := newTestCertSigner(t.Context(), t, ca, zap.NewNop())
	require.ErrorIs(t, err, errSignFailed)

	assert.Zero(t, ca.subscriberCount())
}

func TestAutoRenewingCertSigner_LogsRenewalFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		core, logs := observer.New(zapcore.ErrorLevel)

		ca := newStubCA(t, nil)

		signer, err := newTestCertSigner(ctx, t, ca, zap.New(core))
		require.NoError(t, err)

		go signer.renewalLoop(ctx)

		ca.failFrom(2)

		time.Sleep(80 * time.Minute)
		synctest.Wait()

		entries := logs.FilterMessage("Failed to renew the Gateway's certificate").All()
		require.NotEmpty(t, entries, "a failing renewal is the only warning while handshakes still succeed")
		assert.Equal(t, signedCert(t, signer).ValidBefore, mustUint64(entries[0].ContextMap()["expires_at"].(time.Time)),
			"the log should say how long the CA has to recover")
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
