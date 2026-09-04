// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	lru "github.com/hashicorp/golang-lru/v2"

	"gateway/internal/config"
	"gateway/test/data"
)

// stubIssuer issues placeholder certificates, reporting each issuance start on entered
// and blocking hosts that have a gate until their gate closes. Configure gates before
// the first issuance.
type stubIssuer struct {
	entered  chan string
	gates    map[string]chan struct{}
	rotateCh chan struct{}

	serials atomic.Int64
}

func newStubIssuer() *stubIssuer {
	return &stubIssuer{
		entered:  make(chan string, 16),
		gates:    map[string]chan struct{}{},
		rotateCh: make(chan struct{}, 1),
	}
}

func (s *stubIssuer) run(context.Context) {}

func (s *stubIssuer) rotated() <-chan struct{} { return s.rotateCh }

func (s *stubIssuer) issue(_ context.Context, names []string) (*tls.Certificate, error) {
	s.entered <- names[0]

	if gate, ok := s.gates[names[0]]; ok {
		<-gate
	}

	now := time.Now()

	return &tls.Certificate{Leaf: &x509.Certificate{
		SerialNumber: big.NewInt(s.serials.Add(1)),
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
	}}, nil
}

func newStubAutomation(t *testing.T, issuer certIssuer) *CertAutomation {
	t.Helper()

	cache, err := lru.New[string, *tls.Certificate](maxCachedCerts)
	require.NoError(t, err)

	return &CertAutomation{issuer: issuer, logger: zap.NewNop(), cache: cache}
}

func TestNewCertAutomation_Errors(t *testing.T) {
	nonCA := createKeyPair(t, generateCert(t))

	tests := []struct {
		name        string
		local       *config.TLSLocalIssuerConfig
		key         config.TLSCertificateKeyConfig
		wantErr     error
		errContains string
	}{
		{
			name:    "missing local issuer",
			wantErr: config.ErrMissingTLSIssuerConfig,
		},
		{
			name:    "unsupported key type",
			local:   &config.TLSLocalIssuerConfig{CertificateFile: "../../test/data/proxy/tls.crt", PrivateKeyFile: "../../test/data/proxy/tls.key"},
			key:     config.TLSCertificateKeyConfig{Type: "ed25519"},
			wantErr: errUnsupportedKeyType,
		},
		{
			name:    "unsupported key bits",
			local:   &config.TLSLocalIssuerConfig{CertificateFile: "../../test/data/proxy/tls.crt", PrivateKeyFile: "../../test/data/proxy/tls.key"},
			key:     config.TLSCertificateKeyConfig{Type: "ecdsa", Bits: 128},
			wantErr: errUnsupportedKeyBits,
		},
		{
			name:        "missing files",
			local:       &config.TLSLocalIssuerConfig{CertificateFile: "missing.crt", PrivateKeyFile: "missing.key"},
			errContains: "failed to load CA key pair",
		},
		{
			name:        "mismatched certificate and key",
			local:       &config.TLSLocalIssuerConfig{CertificateFile: "../../test/data/proxy/tls.crt", PrivateKeyFile: "../../test/data/api_server/tls.key"},
			errContains: "failed to load CA key pair",
		},
		{
			name:    "certificate is not a CA",
			local:   &config.TLSLocalIssuerConfig{CertificateFile: nonCA.CertificateFile, PrivateKeyFile: nonCA.PrivateKeyFile},
			wantErr: errNotCACertificate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCertAutomation(config.TLSAutomationConfig{
				Certificate: config.TLSAutomationCertificateConfig{Key: tt.key},
				Issuer:      config.TLSIssuerConfig{Local: tt.local},
			}, zap.NewNop())

			require.Error(t, err)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			}

			if tt.errContains != "" {
				assert.Contains(t, err.Error(), tt.errContains)
			}
		})
	}
}

func TestCertAutomation_GetCertificateForHost_DNSHost(t *testing.T) {
	cert, err := NewCertAutomation(*testAutomationConfig(), zap.NewNop())
	require.NoError(t, err)

	issued, err := cert.GetCertificateForHost(t.Context(), "app.internal", "alt1.internal", "alt2.internal")
	require.NoError(t, err)

	assert.Equal(t, "app.internal", issued.Leaf.Subject.CommonName)
	assert.Equal(t, []string{"app.internal", "alt1.internal", "alt2.internal"}, issued.Leaf.DNSNames)
	assert.WithinDuration(t, time.Now().Add(24*time.Hour), issued.Leaf.NotAfter, time.Minute)

	key, ok := issued.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected an ECDSA leaf key by default")
	assert.Equal(t, elliptic.P256(), key.Curve)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(data.ProxyCert)

	_, err = issued.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "app.internal",
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err, "leaf should verify against the CA for the requested host")

	cached, ok := cert.cache.Get("app.internal,alt1.internal,alt2.internal")
	require.True(t, ok, "the issued certificate should be cached under its name set")
	assert.Same(t, issued, cached)
}

func TestCertAutomation_GetCertificateForHost_IPHost(t *testing.T) {
	cert, err := NewCertAutomation(*testAutomationConfig(), zap.NewNop())
	require.NoError(t, err)

	issued, err := cert.GetCertificateForHost(t.Context(), "10.0.0.5", "alt.internal")
	require.NoError(t, err)

	require.Len(t, issued.Leaf.IPAddresses, 1)
	assert.True(t, issued.Leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")))
	assert.Equal(t, []string{"alt.internal"}, issued.Leaf.DNSNames)

	cached, ok := cert.cache.Get("10.0.0.5,alt.internal")
	require.True(t, ok, "the issued certificate should be cached under its name set")
	assert.Same(t, issued, cached)
}

func TestCertAutomation_Run_ReissuesAfterCARotation(t *testing.T) {
	ca := generateCA(t)
	file := createKeyPair(t, ca)

	cfg := testAutomationConfig()
	cfg.Issuer.Local = &config.TLSLocalIssuerConfig{CertificateFile: file.CertificateFile, PrivateKeyFile: file.PrivateKeyFile}

	cert, err := NewCertAutomation(*cfg, zap.NewNop())
	require.NoError(t, err)

	cert.Run(t.Context())

	issued, err := cert.GetCertificateForHost(t.Context(), "app.acme.int")
	require.NoError(t, err)

	_, err = issued.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "app.acme.int",
		Roots:     caPool(t, ca),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err)

	rotated := generateCA(t)
	rotatedPool := caPool(t, rotated)
	replaceKeyPair(t, file, rotated)

	// The reload and the cache purge are both asynchronous.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		got, err := cert.GetCertificateForHost(t.Context(), "app.acme.int")
		require.NoError(c, err)
		require.NotEqual(c, issued.Leaf.SerialNumber, got.Leaf.SerialNumber, "the cached certificate should have been dropped")

		_, verifyErr := got.Leaf.Verify(x509.VerifyOptions{
			DNSName:   "app.acme.int",
			Roots:     rotatedPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		require.NoError(c, verifyErr, "the reissued certificate should chain to the rotated CA")
	}, 5*time.Second, 10*time.Millisecond)
}

func TestCertAutomation_GetCertificateForHost_KeyConfig(t *testing.T) {
	cfg := testAutomationConfig()
	cfg.Certificate.Key = config.TLSCertificateKeyConfig{Type: "rsa", Bits: 2048}

	cert, err := NewCertAutomation(*cfg, zap.NewNop())
	require.NoError(t, err)

	issued, err := cert.GetCertificateForHost(t.Context(), "app.internal")
	require.NoError(t, err)

	key, ok := issued.PrivateKey.(*rsa.PrivateKey)
	require.True(t, ok, "expected an RSA leaf key")
	assert.Equal(t, 2048, key.N.BitLen())
}

func TestCertAutomation_GetCertificateForHost_CachesPerNameSet(t *testing.T) {
	cert, err := NewCertAutomation(*testAutomationConfig(), zap.NewNop())
	require.NoError(t, err)

	first, err := cert.GetCertificateForHost(t.Context(), "app.internal", "a.internal")
	require.NoError(t, err)

	// The same host with a different alias set needs its own certificate.
	other, err := cert.GetCertificateForHost(t.Context(), "app.internal", "b.internal")
	require.NoError(t, err)
	assert.NotEqual(t, first.Leaf.SerialNumber, other.Leaf.SerialNumber)

	again, err := cert.GetCertificateForHost(t.Context(), "app.internal", "a.internal")
	require.NoError(t, err)
	assert.Same(t, first, again)

	// The same aliases in a different order are the same name set.
	sorted, err := cert.GetCertificateForHost(t.Context(), "app.internal", "a.internal", "b.internal")
	require.NoError(t, err)

	reordered, err := cert.GetCertificateForHost(t.Context(), "app.internal", "b.internal", "a.internal")
	require.NoError(t, err)
	assert.Same(t, sorted, reordered)
}

func TestCertAutomation_GetCertificateForHost_RenewsPastThreshold(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := testAutomationConfig()
		cfg.Certificate.TTL = 2 * time.Hour

		cert, err := NewCertAutomation(*cfg, zap.NewNop())
		require.NoError(t, err)

		first, err := cert.GetCertificateForHost(t.Context(), "app.internal")
		require.NoError(t, err)

		// A fresh certificate is well short of its renewal threshold.
		again, err := cert.GetCertificateForHost(t.Context(), "app.internal")
		require.NoError(t, err)
		assert.Same(t, first, again)

		// Move past 80% of the certificate's lifetime, but short of its expiry.
		time.Sleep(100 * time.Minute)

		second, err := cert.GetCertificateForHost(t.Context(), "app.internal")
		require.NoError(t, err)

		assert.NotEqual(t, first.Leaf.SerialNumber, second.Leaf.SerialNumber)

		// Re-issuing replaces the cached entry rather than adding another one.
		assert.Equal(t, 1, cert.cache.Len())
	})
}

// Concurrent cold misses for one host may each sign their own certificate, since
// signing outside the lock keeps a slow CA from stalling handshakes for other names.
// The cache still converges to one certificate per name set.
func TestCertAutomation_GetCertificateForHost_ConcurrentColdMissesConverge(t *testing.T) {
	const callers = 10

	cert, err := NewCertAutomation(*testAutomationConfig(), zap.NewNop())
	require.NoError(t, err)

	var wg sync.WaitGroup

	errs := make([]error, callers)
	start := make(chan struct{})

	for i := range callers {
		wg.Go(func() {
			<-start

			_, errs[i] = cert.GetCertificateForHost(t.Context(), "cold.internal")
		})
	}

	close(start)
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}

	require.Equal(t, 1, cert.cache.Len())

	cached, ok := cert.cache.Get("cold.internal")
	require.True(t, ok)

	again, err := cert.GetCertificateForHost(t.Context(), "cold.internal")
	require.NoError(t, err)
	assert.Same(t, cached, again, "a warm cache should serve without signing")
}

// A slow CA must not stall handshakes for other name sets: only callers for the
// gated host wait on its issuance.
func TestCertAutomation_GetCertificateForHost_SlowIssuanceDoesNotBlockOtherHosts(t *testing.T) {
	issuer := newStubIssuer()
	gate := make(chan struct{})
	issuer.gates["slow.acme.int"] = gate

	openGate := sync.OnceFunc(func() { close(gate) })
	defer openGate()

	automation := newStubAutomation(t, issuer)

	slowDone := make(chan error, 1)

	go func() {
		_, err := automation.GetCertificateForHost(t.Context(), "slow.acme.int")
		slowDone <- err
	}()

	require.Equal(t, "slow.acme.int", <-issuer.entered, "slow issuance should be in flight")

	fastDone := make(chan error, 1)

	go func() {
		_, err := automation.GetCertificateForHost(t.Context(), "fast.acme.int")
		fastDone <- err
	}()

	select {
	case err := <-fastDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("issuance for one host blocked a handshake for another")
	}

	openGate()
	require.NoError(t, <-slowDone)
}

// A certificate whose issuance was in flight when the CA rotated is served to that
// handshake only; the cache never holds a certificate from a previous CA.
func TestCertAutomation_GetCertificateForHost_RotationMidIssuanceIsNotCached(t *testing.T) {
	issuer := newStubIssuer()
	gate := make(chan struct{})
	issuer.gates["app.acme.int"] = gate

	automation := newStubAutomation(t, issuer)
	automation.Run(t.Context())

	type result struct {
		cert *tls.Certificate
		err  error
	}

	done := make(chan result, 1)

	go func() {
		cert, err := automation.GetCertificateForHost(t.Context(), "app.acme.int")
		done <- result{cert, err}
	}()

	require.Equal(t, "app.acme.int", <-issuer.entered, "issuance should be in flight")

	issuer.rotateCh <- struct{}{}

	// Wait for the purge, so releasing the issuance cannot race it.
	require.Eventually(t, func() bool {
		automation.mu.Lock()
		defer automation.mu.Unlock()

		return automation.caRotations > 0
	}, 5*time.Second, time.Millisecond)

	close(gate)

	first := <-done
	require.NoError(t, first.err)

	_, cached := automation.cache.Get("app.acme.int")
	assert.False(t, cached, "a certificate signed by the previous CA must not be cached")

	second, err := automation.GetCertificateForHost(t.Context(), "app.acme.int")
	require.NoError(t, err)
	assert.NotEqual(t, first.cert.Leaf.SerialNumber, second.Leaf.SerialNumber,
		"the next handshake should get a certificate from the current CA")
}

func TestCertNames(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		aliases []string
		want    []string
	}{
		{
			name:    "aliases are sorted after the host",
			host:    "app.internal",
			aliases: []string{"b.internal", "a.internal"},
			want:    []string{"app.internal", "a.internal", "b.internal"},
		},
		{
			name:    "ip host with dns aliases",
			host:    "10.0.0.5",
			aliases: []string{"app.internal", "alt.internal"},
			want:    []string{"10.0.0.5", "alt.internal", "app.internal"},
		},
		{
			name:    "alias repeating the host is not duplicated",
			host:    "app.internal",
			aliases: []string{"app.internal", "alt.internal", ""},
			want:    []string{"app.internal", "alt.internal"},
		},
		{
			name: "no aliases",
			host: "app.internal",
			want: []string{"app.internal"},
		},
		{
			name:    "wildcard host stays first",
			host:    "*.internal",
			aliases: []string{"app.internal", "alt.internal"},
			want:    []string{"*.internal", "alt.internal", "app.internal"},
		},
		{
			name:    "names are lowercased",
			host:    "APP.Internal",
			aliases: []string{"ALT.Internal"},
			want:    []string{"app.internal", "alt.internal"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, certNames(tt.host, tt.aliases))
		})
	}
}
