// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	lru "github.com/hashicorp/golang-lru/v2"

	"gateway/internal/config"
)

var (
	errStubRun  = errors.New("stub issuer failed to start")
	errStubSign = errors.New("stub issuer failed to sign")
)

// stubIssuer signs placeholder certificates, calling onSign at the start of every
// signing so a test can inspect the request or hold the issuance. Set onSign before
// the first request.
type stubIssuer struct {
	onSign  func(req *certificateRequest)
	runErr  error
	signErr error

	serials atomic.Int64
}

func newStubIssuer() *stubIssuer {
	return &stubIssuer{}
}

func (s *stubIssuer) run(context.Context) error { return s.runErr }

func (s *stubIssuer) sign(_ context.Context, req *certificateRequest) (*x509.Certificate, []*x509.Certificate, error) {
	if s.onSign != nil {
		s.onSign(req)
	}

	if s.signErr != nil {
		return nil, nil, s.signErr
	}

	now := time.Now()

	return &x509.Certificate{
		SerialNumber: big.NewInt(s.serials.Add(1)),
		NotBefore:    now,
		NotAfter:     now.Add(req.ttl),
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
		vault       *config.TLSVaultIssuerConfig
		key         config.TLSCertificateKeyConfig
		wantErr     error
		errContains string
	}{
		{
			name:    "missing issuer",
			wantErr: config.ErrMissingTLSIssuerConfig,
		},
		{
			name: "vault CA bundle missing",
			vault: &config.TLSVaultIssuerConfig{
				Address: "https://vault.acme.int:8200", CABundleFile: "missing.crt",
				Role: "gateway",
			},
			errContains: "failed to create Vault client",
		},
		{
			name:    "unsupported key type",
			local:   &config.TLSLocalIssuerConfig{CertificateFile: "../../../test/data/proxy/tls.crt", PrivateKeyFile: "../../../test/data/proxy/tls.key"},
			key:     config.TLSCertificateKeyConfig{Type: "ed25519"},
			wantErr: errUnsupportedKeyType,
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
				Issuer:      config.TLSIssuerConfig{Local: tt.local, Vault: tt.vault},
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

func TestAutomation_run_IssuerFailsToStart(t *testing.T) {
	issuer := newStubIssuer()
	issuer.runErr = errStubRun

	require.ErrorIs(t, newStubAutomation(t, issuer).run(t.Context()), errStubRun)
}

func TestNewAutomation_VaultIssuer(t *testing.T) {
	automation, err := newAutomation(&config.TLSAutomationConfig{
		Issuer: config.TLSIssuerConfig{Vault: &config.TLSVaultIssuerConfig{
			Address: "https://vault.acme.int:8200",
			Role:    "gateway",
		}},
	}, zap.NewNop())

	require.NoError(t, err)
	assert.IsType(t, &vaultIssuer{}, automation.issuer)
}

func TestAutomation_run_ReissuesAfterCARotation(t *testing.T) {
	ca := generateCA(t)
	file := createKeyPair(t, ca)
	cert, err := newAutomation(
		&config.TLSAutomationConfig{
			Issuer: config.TLSIssuerConfig{
				Local: &config.TLSLocalIssuerConfig{CertificateFile: file.CertificateFile, PrivateKeyFile: file.PrivateKeyFile},
			},
		},
		zap.NewNop(),
	)
	require.NoError(t, err)

	require.NoError(t, cert.run(t.Context()))

	issued, err := cert.getCertificate(t.Context(), "app.acme.int")
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
		got, err := cert.getCertificate(t.Context(), "app.acme.int")
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

func TestAutomation_issue(t *testing.T) {
	ca := generateCA(t)
	file := createKeyPair(t, ca)
	cert, err := newAutomation(
		&config.TLSAutomationConfig{
			Issuer: config.TLSIssuerConfig{
				Local: &config.TLSLocalIssuerConfig{CertificateFile: file.CertificateFile, PrivateKeyFile: file.PrivateKeyFile},
			},
		},
		zap.NewNop(),
	)
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

func TestAutomation_getCertificate(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		wantKey  string
		wantSANs []string
	}{
		{
			name:     "the host is lowercased",
			host:     "APP.internal",
			wantKey:  "app.internal",
			wantSANs: []string{"app.internal"},
		},
		{
			name:    "a handshake without SNI gets a nameless certificate",
			host:    "",
			wantKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := newStubIssuer()

			var signed *certificateRequest

			issuer.onSign = func(req *certificateRequest) { signed = req }

			cert := newStubAutomation(t, issuer)

			issued, err := cert.getCertificate(t.Context(), tt.host)
			require.NoError(t, err)
			assert.Equal(t, tt.wantSANs, requestSANs(signed), "the issuer should be asked for the normalized host")

			cached, ok := cert.cache.Get(tt.wantKey)
			require.True(t, ok, "the issued certificate should be cached under its host")
			assert.Same(t, issued, cached)
		})
	}
}

func TestAutomation_getCertificate_SigningFails(t *testing.T) {
	issuer := newStubIssuer()
	issuer.signErr = errStubSign

	cert := newStubAutomation(t, issuer)

	_, err := cert.getCertificate(t.Context(), "app.acme.int")
	require.ErrorIs(t, err, errStubSign)
	assert.Zero(t, cert.cache.Len(), "a failed issuance should cache nothing")
}

// Concurrent cold misses for one host may each sign their own certificate, since
// signing outside the lock keeps a slow CA from stalling handshakes for other names.
// The cache still converges to one certificate per hostname.
func TestAutomation_getCertificate_ConcurrentColdMissesConverge(t *testing.T) {
	const callers = 10

	cert := newStubAutomation(t, newStubIssuer())

	start := make(chan struct{})

	var wg sync.WaitGroup

	for range callers {
		wg.Go(func() {
			<-start

			_, err := cert.getCertificate(t.Context(), "cold.internal")
			assert.NoError(t, err)
		})
	}

	close(start)
	wg.Wait()

	assert.Equal(t, 1, cert.cache.Len())
}

func TestAutomation_getCertificate_SlowIssuanceDoesNotBlockOtherHosts(t *testing.T) {
	slowSigning := make(chan struct{}, 1)
	slowRelease := make(chan struct{})

	issuer := newStubIssuer()
	issuer.onSign = func(req *certificateRequest) {
		if !slices.Contains(req.dnsNames, "slow.acme.int") {
			return
		}

		slowSigning <- struct{}{}

		<-slowRelease
	}

	release := sync.OnceFunc(func() { close(slowRelease) })
	defer release()

	automation := newStubAutomation(t, issuer)

	slowDone := make(chan error, 1)

	go func() {
		_, err := automation.getCertificate(t.Context(), "slow.acme.int")
		slowDone <- err
	}()

	<-slowSigning

	fastDone := make(chan error, 1)

	go func() {
		_, err := automation.getCertificate(t.Context(), "fast.acme.int")
		fastDone <- err
	}()

	select {
	case err := <-fastDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("issuance for one host blocked a handshake for another")
	}

	release()
	require.NoError(t, <-slowDone)
}

// A certificate whose issuance was in flight when the CA rotated is served to that
// handshake only; the cache never holds a certificate from a previous CA.
func TestAutomation_getCertificate_RotationMidIssuanceIsNotCached(t *testing.T) {
	slowSigning := make(chan struct{}, 1)
	rotated := make(chan struct{})

	issuer := newStubIssuer()
	issuer.onSign = func(*certificateRequest) {
		slowSigning <- struct{}{}

		<-rotated
	}

	automation := newStubAutomation(t, issuer)

	done := make(chan *tls.Certificate, 1)

	go func() {
		cert, err := automation.getCertificate(t.Context(), "app.acme.int")
		assert.NoError(t, err)

		done <- cert
	}()

	<-slowSigning

	// The CA rotates while the issuance is in flight.
	automation.mu.Lock()
	automation.caRotations++
	automation.mu.Unlock()

	close(rotated)

	first := <-done
	require.NotNil(t, first)

	_, cached := automation.cache.Get("app.acme.int")
	assert.False(t, cached, "a certificate signed by the previous CA must not be cached")

	second, err := automation.getCertificate(t.Context(), "app.acme.int")
	require.NoError(t, err)
	assert.NotEqual(t, first.Leaf.SerialNumber, second.Leaf.SerialNumber,
		"the next handshake should get a certificate from the current CA")
}

func TestAutomation_cachedCert(t *testing.T) {
	tests := []struct {
		name      string
		remaining time.Duration
		want      bool
	}{
		{
			name:      "a certificate clear of the buffer is served",
			remaining: 2 * expiryBuffer,
			want:      true,
		},
		{
			name:      "a certificate at the buffer is not served",
			remaining: expiryBuffer,
		},
		{
			name:      "a certificate inside the buffer is not served, though it is still valid",
			remaining: expiryBuffer / 2,
		},
		{
			name:      "an expired certificate is not served",
			remaining: -time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := newStubAutomation(t, newStubIssuer())

			cached := &tls.Certificate{Leaf: &x509.Certificate{NotAfter: time.Now().Add(tt.remaining)}}
			cert.cache.Add("app.internal", cached)

			got := cert.cachedCert("app.internal")

			if tt.want {
				assert.Same(t, cached, got)

				return
			}

			assert.Nil(t, got)
		})
	}
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

			assert.Equal(t, tt.wantNames, requestSANs(req))
			assert.Equal(t, defaultTTL, req.ttl)
			assert.Equal(t, key, req.key)

			der, err := req.csr()
			require.NoError(t, err)

			csr, err := x509.ParseCertificateRequest(der)
			require.NoError(t, err)

			// A backend reads the names off the request but forwards the CSR, so the two
			// have to agree, and the CSR has to prove possession of the key it asks for.
			assert.Equal(t, requestSANs(req), csrSANs(csr))
			assert.Empty(t, csr.Subject.CommonName)
			assert.NoError(t, csr.CheckSignature())
		})
	}
}

func csrSANs(csr *x509.CertificateRequest) []string {
	names := slices.Clone(csr.DNSNames)
	for _, ip := range csr.IPAddresses {
		names = append(names, ip.String())
	}

	return names
}

func requestSANs(req *certificateRequest) []string {
	names := slices.Clone(req.dnsNames)
	for _, ip := range req.ipAddresses {
		names = append(names, ip.String())
	}

	return names
}
