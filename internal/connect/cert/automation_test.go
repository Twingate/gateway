// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"slices"
	"strings"
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

var (
	errStubRun  = errors.New("stub issuer failed to start")
	errStubSign = errors.New("stub issuer failed to sign")
)

// stubIssuer signs placeholder certificates, reporting each signing start on entered
// and blocking requests for a host that has a gate until their gate closes. Configure
// gates before the first request.
type stubIssuer struct {
	entered  chan string
	gates    map[string]chan struct{}
	rotateCh chan struct{}
	runErr   error
	signErr  error

	serials atomic.Int64
}

func newStubIssuer() *stubIssuer {
	return &stubIssuer{
		entered:  make(chan string, 16),
		gates:    map[string]chan struct{}{},
		rotateCh: make(chan struct{}, 1),
	}
}

func (s *stubIssuer) run(context.Context) error { return s.runErr }

func (s *stubIssuer) rotated() <-chan struct{} { return s.rotateCh }

func (s *stubIssuer) sign(_ context.Context, req *certificateRequest) (*x509.Certificate, []*x509.Certificate, error) {
	name := strings.Join(requestNames(req), ",")
	s.entered <- name

	if gate, ok := s.gates[name]; ok {
		<-gate
	}

	if s.signErr != nil {
		return nil, nil, s.signErr
	}

	now := time.Now()

	return &x509.Certificate{
		SerialNumber: big.NewInt(s.serials.Add(1)),
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
	}, nil, nil
}

func newStubAutomation(t *testing.T, issuer issuer) *automation {
	t.Helper()

	cache, err := lru.New[string, *tls.Certificate](maxCachedCerts)
	require.NoError(t, err)

	return &automation{
		issuer: issuer,
		key:    keyConfig{typ: keyTypeECDSA, bits: 256},
		ttl:    defaultTTL,
		logger: zap.NewNop(),
		cache:  cache,
	}
}

func TestNewAutomation_Errors(t *testing.T) {
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
			local:   &config.TLSLocalIssuerConfig{CertificateFile: "../../../test/data/proxy/tls.crt", PrivateKeyFile: "../../../test/data/proxy/tls.key"},
			key:     config.TLSCertificateKeyConfig{Type: "ed25519"},
			wantErr: errUnsupportedKeyType,
		},
		{
			name:    "unsupported key bits",
			local:   &config.TLSLocalIssuerConfig{CertificateFile: "../../../test/data/proxy/tls.crt", PrivateKeyFile: "../../../test/data/proxy/tls.key"},
			key:     config.TLSCertificateKeyConfig{Type: "ecdsa", Bits: 128},
			wantErr: errUnsupportedKeyBits,
		},
		{
			// Issuer construction failures propagate; the cases live with the issuer's own tests.
			name:        "issuer fails to load",
			local:       &config.TLSLocalIssuerConfig{CertificateFile: "missing.crt", PrivateKeyFile: "missing.key"},
			errContains: "failed to load CA key pair",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newAutomation(&config.TLSAutomationConfig{
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

func TestAutomation_Run_IssuerFailsToStart(t *testing.T) {
	issuer := newStubIssuer()
	issuer.runErr = errStubRun

	require.ErrorIs(t, newStubAutomation(t, issuer).run(t.Context()), errStubRun)
}

func TestAutomation_issue(t *testing.T) {
	ca := generateCA(t)
	file := createKeyPair(t, ca)

	cfg := testAutomationConfig()
	cfg.Issuer.Local = &config.TLSLocalIssuerConfig{CertificateFile: file.CertificateFile, PrivateKeyFile: file.PrivateKeyFile}

	cert, err := newAutomation(cfg, zap.NewNop())
	require.NoError(t, err)

	issued, err := cert.issue(t.Context(), "app.acme.int")
	require.NoError(t, err)

	require.Len(t, issued.Certificate, 2)
	assert.Equal(t, issued.Leaf.Raw, issued.Certificate[0], "the leaf should come first in the chain")
	assert.Equal(t, ca.Certificate[0], issued.Certificate[1])

	key, ok := issued.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected an ECDSA leaf key")
	assert.True(t, key.PublicKey.Equal(issued.Leaf.PublicKey), "the served key should be the one the leaf was signed for")
}

// A key config that generate rejects cannot come from newAutomation, which validates it first.
func TestAutomation_issue_KeyGenerationFails(t *testing.T) {
	cert := newStubAutomation(t, newStubIssuer())
	cert.key = keyConfig{typ: keyTypeECDSA, bits: 128}

	_, err := cert.issue(t.Context(), "app.acme.int")
	require.ErrorIs(t, err, errUnsupportedKeyBits)
	assert.Contains(t, err.Error(), "failed to generate leaf key")
}

func TestAutomation_getCertificateForHost(t *testing.T) {
	cert, err := newAutomation(testAutomationConfig(), zap.NewNop())
	require.NoError(t, err)

	// hostname is lowercased
	issued, err := cert.getCertificateForHost(t.Context(), "APP.internal")
	require.NoError(t, err)

	assert.Equal(t, []string{"app.internal"}, issued.Leaf.DNSNames)
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

	cached, ok := cert.cache.Get("app.internal")
	require.True(t, ok, "the issued certificate should be cached under its host")
	assert.Same(t, issued, cached)
}

func TestAutomation_getCertificateForHost_EmptyHost(t *testing.T) {
	cert, err := newAutomation(testAutomationConfig(), zap.NewNop())
	require.NoError(t, err)

	issued, err := cert.getCertificateForHost(t.Context(), "")
	require.NoError(t, err)

	assert.Empty(t, issued.Leaf.DNSNames)
	assert.Empty(t, issued.Leaf.IPAddresses)
	assert.Empty(t, issued.Leaf.Subject.CommonName)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(data.ProxyCert)

	_, err = issued.Leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err, "leaf should still chain to the CA")

	cached, ok := cert.cache.Get("")
	require.True(t, ok, "the nameless certificate should be cached under the empty host")
	assert.Same(t, issued, cached)
}

func TestAutomation_getCertificateForHost_SigningFails(t *testing.T) {
	issuer := newStubIssuer()
	issuer.signErr = errStubSign

	cert := newStubAutomation(t, issuer)

	_, err := cert.getCertificateForHost(t.Context(), "app.acme.int")
	require.ErrorIs(t, err, errStubSign)
	assert.Zero(t, cert.cache.Len(), "a failed issuance should cache nothing")
}

func TestAutomation_Run_ReissuesAfterCARotation(t *testing.T) {
	ca := generateCA(t)
	file := createKeyPair(t, ca)

	cfg := testAutomationConfig()
	cfg.Issuer.Local = &config.TLSLocalIssuerConfig{CertificateFile: file.CertificateFile, PrivateKeyFile: file.PrivateKeyFile}

	cert, err := newAutomation(cfg, zap.NewNop())
	require.NoError(t, err)

	require.NoError(t, cert.run(t.Context()))

	issued, err := cert.getCertificateForHost(t.Context(), "app.acme.int")
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
		got, err := cert.getCertificateForHost(t.Context(), "app.acme.int")
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

func TestAutomation_getCertificateForHost_ReissuesAfterExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := testAutomationConfig()
		cfg.Certificate.TTL = 2 * time.Hour

		cert, err := newAutomation(cfg, zap.NewNop())
		require.NoError(t, err)

		first, err := cert.getCertificateForHost(t.Context(), "app.internal")
		require.NoError(t, err)

		// Move the certificate's lifetime close to its expiry.
		time.Sleep(119 * time.Minute)

		again, err := cert.getCertificateForHost(t.Context(), "app.internal")
		require.NoError(t, err)
		assert.Same(t, first, again)

		time.Sleep(2*time.Minute + time.Second)

		second, err := cert.getCertificateForHost(t.Context(), "app.internal")
		require.NoError(t, err)

		assert.NotEqual(t, first.Leaf.SerialNumber, second.Leaf.SerialNumber)

		// Re-issuing replaces the cached entry rather than adding another one.
		assert.Equal(t, 1, cert.cache.Len())
	})
}

// Concurrent cold misses for one host may each sign their own certificate, since
// signing outside the lock keeps a slow CA from stalling handshakes for other names.
// The cache still converges to one certificate per hostname.
func TestAutomation_getCertificateForHost_ConcurrentColdMissesConverge(t *testing.T) {
	const callers = 10

	cert, err := newAutomation(testAutomationConfig(), zap.NewNop())
	require.NoError(t, err)

	var wg sync.WaitGroup

	errs := make([]error, callers)
	start := make(chan struct{})

	for i := range callers {
		wg.Go(func() {
			<-start

			_, errs[i] = cert.getCertificateForHost(t.Context(), "cold.internal")
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

	again, err := cert.getCertificateForHost(t.Context(), "cold.internal")
	require.NoError(t, err)
	assert.Same(t, cached, again, "a warm cache should serve without signing")
}

// A slow CA must not stall handshakes for other names: only callers for the
// gated host wait on its issuance.
func TestAutomation_getCertificateForHost_SlowIssuanceDoesNotBlockOtherHosts(t *testing.T) {
	issuer := newStubIssuer()
	gate := make(chan struct{})
	issuer.gates["slow.acme.int"] = gate

	openGate := sync.OnceFunc(func() { close(gate) })
	defer openGate()

	automation := newStubAutomation(t, issuer)

	slowDone := make(chan error, 1)

	go func() {
		_, err := automation.getCertificateForHost(t.Context(), "slow.acme.int")
		slowDone <- err
	}()

	require.Equal(t, "slow.acme.int", <-issuer.entered, "slow issuance should be in flight")

	fastDone := make(chan error, 1)

	go func() {
		_, err := automation.getCertificateForHost(t.Context(), "fast.acme.int")
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
func TestAutomation_getCertificateForHost_RotationMidIssuanceIsNotCached(t *testing.T) {
	issuer := newStubIssuer()
	gate := make(chan struct{})
	issuer.gates["app.acme.int"] = gate

	automation := newStubAutomation(t, issuer)
	require.NoError(t, automation.run(t.Context()))

	type result struct {
		cert *tls.Certificate
		err  error
	}

	done := make(chan result, 1)

	go func() {
		cert, err := automation.getCertificateForHost(t.Context(), "app.acme.int")
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

	second, err := automation.getCertificateForHost(t.Context(), "app.acme.int")
	require.NoError(t, err)
	assert.NotEqual(t, first.cert.Leaf.SerialNumber, second.Leaf.SerialNumber,
		"the next handshake should get a certificate from the current CA")
}

func TestNewCertificateRequest(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		wantNames []string
	}{
		{
			name:      "hostname becomes a DNS name",
			host:      "app.acme.int",
			wantNames: []string{"app.acme.int"},
		},
		{
			name:      "IP becomes an IP address",
			host:      "10.0.0.5",
			wantNames: []string{"10.0.0.5"},
		},
		{
			// A handshake without SNI leaves no name to request.
			name: "no host asks for no names",
			host: "",
		},
	}

	key, err := keyConfig{typ: keyTypeECDSA, bits: 256}.generate()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newCertificateRequest(key, tt.host, defaultTTL)

			assert.Equal(t, tt.wantNames, requestNames(req))
			assert.Equal(t, defaultTTL, req.ttl)
			assert.Equal(t, key, req.key)

			der, err := req.csr()
			require.NoError(t, err)

			csr, err := x509.ParseCertificateRequest(der)
			require.NoError(t, err)

			// A backend reads the names off the request but forwards the CSR, so the two
			// have to agree, and the CSR has to prove possession of the key it asks for.
			assert.Equal(t, requestNames(req), csrNames(csr))
			assert.Empty(t, csr.Subject.CommonName)
			assert.NoError(t, csr.CheckSignature())
		})
	}
}

func csrNames(csr *x509.CertificateRequest) []string {
	names := slices.Clone(csr.DNSNames)
	for _, ip := range csr.IPAddresses {
		names = append(names, ip.String())
	}

	return names
}

func requestNames(req *certificateRequest) []string {
	names := slices.Clone(req.dnsNames)
	for _, ip := range req.ipAddresses {
		names = append(names, ip.String())
	}

	return names
}
