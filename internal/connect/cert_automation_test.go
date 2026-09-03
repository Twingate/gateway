// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/config"
	"gateway/test/data"
)

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

	issued, err := cert.GetCertificateForHost(t.Context(), "app.internal")
	require.NoError(t, err)

	assert.Equal(t, "app.internal", issued.Leaf.Subject.CommonName)
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
	assert.NoError(t, err, "leaf should verify against the CA for the requested host")
}

func TestCertAutomation_GetCertificateForHost_IPHost(t *testing.T) {
	cert, err := NewCertAutomation(*testAutomationConfig(), zap.NewNop())
	require.NoError(t, err)

	issued, err := cert.GetCertificateForHost(t.Context(), "10.0.0.5")
	require.NoError(t, err)

	require.Len(t, issued.Leaf.IPAddresses, 1)
	assert.True(t, issued.Leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")))
	assert.Empty(t, issued.Leaf.DNSNames)
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

func TestCertAutomation_GetCertificateForHost_CoversAliases(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		aliases []string
		wantCN  string
		wantDNS []string
		wantIPs []string
	}{
		{
			name:    "aliases are sorted after the host",
			host:    "app.internal",
			aliases: []string{"b.internal", "a.internal"},
			wantCN:  "app.internal",
			wantDNS: []string{"app.internal", "a.internal", "b.internal"},
		},
		{
			name:    "ip host with dns aliases",
			host:    "10.0.0.5",
			aliases: []string{"app.internal", "alt.internal"},
			wantCN:  "10.0.0.5",
			wantDNS: []string{"alt.internal", "app.internal"},
			wantIPs: []string{"10.0.0.5"},
		},
		{
			name:    "dns host with dns aliases",
			host:    "app.internal",
			aliases: []string{"alt.internal"},
			wantCN:  "app.internal",
			wantDNS: []string{"app.internal", "alt.internal"},
		},
		{
			name:    "alias repeating the host is not duplicated",
			host:    "app.internal",
			aliases: []string{"app.internal", "alt.internal", ""},
			wantCN:  "app.internal",
			wantDNS: []string{"app.internal", "alt.internal"},
		},
		{
			name:    "no aliases",
			host:    "app.internal",
			wantCN:  "app.internal",
			wantDNS: []string{"app.internal"},
		},
		{
			name:    "wildcard host stays first",
			host:    "*.internal",
			aliases: []string{"app.internal", "alt.internal"},
			wantCN:  "*.internal",
			wantDNS: []string{"*.internal", "alt.internal", "app.internal"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := NewCertAutomation(*testAutomationConfig(), zap.NewNop())
			require.NoError(t, err)

			issued, err := cert.GetCertificateForHost(t.Context(), tt.host, tt.aliases...)
			require.NoError(t, err)

			assert.Equal(t, tt.wantCN, issued.Leaf.Subject.CommonName)
			assert.Equal(t, tt.wantDNS, issued.Leaf.DNSNames)

			var gotIPs []string
			for _, ip := range issued.Leaf.IPAddresses {
				gotIPs = append(gotIPs, ip.String())
			}

			assert.Equal(t, tt.wantIPs, gotIPs)
		})
	}
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

	// Age the cached certificate past 80% of its lifetime.
	cached, ok := cert.cache.Get("app.internal")
	require.True(t, ok)

	cached.Leaf.NotBefore = time.Now().Add(-2 * time.Hour)
	cached.Leaf.NotAfter = time.Now().Add(10 * time.Minute)

	second, err := cert.GetCertificateForHost(t.Context(), "app.internal")
	require.NoError(t, err)

	assert.NotEqual(t, first.Leaf.SerialNumber, second.Leaf.SerialNumber)

	// Re-issuing replaces the cached entry rather than adding another one.
	assert.Equal(t, 1, cert.cache.Len())
}

// Concurrent cold misses for one host must issue once. This is what the
// re-check inside the lock in GetCertificateForHost buys; without it every
// caller issues its own certificate.
func TestCertAutomation_GetCertificateForHost_ConcurrentColdMissIssuesOnce(t *testing.T) {
	const callers = 10

	cert, err := NewCertAutomation(*testAutomationConfig(), zap.NewNop())
	require.NoError(t, err)

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		issueErr error
		serials  = map[string]struct{}{}
	)

	start := make(chan struct{})

	for range callers {
		wg.Go(func() {
			<-start

			got, err := cert.GetCertificateForHost(t.Context(), "cold.internal")

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				issueErr = err

				return
			}

			serials[got.Leaf.SerialNumber.String()] = struct{}{}
		})
	}

	close(start)
	wg.Wait()

	require.NoError(t, issueErr)
	assert.Len(t, serials, 1, "concurrent cold misses should issue exactly once")
	assert.Equal(t, 1, cert.cache.Len())
}
