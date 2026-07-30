// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

func TestNewDynamicCert_Errors(t *testing.T) {
	nonCAFile, nonCAKeyFile := createCertFiles(t, generateCert(t))

	tests := []struct {
		name        string
		selfSign    *config.TLSSelfSignCAConfig
		wantErr     error
		errContains string
	}{
		{
			name:    "missing selfSign",
			wantErr: config.ErrMissingTLSCAConfig,
		},
		{
			name:        "missing files",
			selfSign:    &config.TLSSelfSignCAConfig{CertificateFile: "missing.crt", PrivateKeyFile: "missing.key"},
			errContains: "failed to load CA key pair",
		},
		{
			name:        "mismatched certificate and key",
			selfSign:    &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/proxy/tls.crt", PrivateKeyFile: "../../test/data/api_server/tls.key"},
			errContains: "failed to load CA key pair",
		},
		{
			name:     "certificate is not a CA",
			selfSign: &config.TLSSelfSignCAConfig{CertificateFile: nonCAFile, PrivateKeyFile: nonCAKeyFile},
			wantErr:  errNotCACertificate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDynamicCert(config.TLSDynamicConfig{
				CA: config.TLSDynamicCAConfig{SelfSign: tt.selfSign},
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

func TestDynamicCert_GetCertificateForHost_DNSHost(t *testing.T) {
	cert, err := NewDynamicCert(config.TLSDynamicConfig{
		CA: config.TLSDynamicCAConfig{
			SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/proxy/tls.crt", PrivateKeyFile: "../../test/data/proxy/tls.key"},
		},
	}, zap.NewNop())
	require.NoError(t, err)

	minted, err := cert.GetCertificateForHost("app.internal")
	require.NoError(t, err)

	assert.Equal(t, "app.internal", minted.Leaf.Subject.CommonName)
	assert.Equal(t, []string{"app.internal"}, minted.Leaf.DNSNames)
	assert.WithinDuration(t, time.Now().Add(24*time.Hour), minted.Leaf.NotAfter, time.Minute)

	key, ok := minted.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected an ECDSA leaf key by default")
	assert.Equal(t, elliptic.P256(), key.Curve)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(data.ProxyCert)

	_, err = minted.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "app.internal",
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	assert.NoError(t, err, "leaf should verify against the CA for the requested host")
}

func TestDynamicCert_GetCertificateForHost_IPHost(t *testing.T) {
	cert, err := NewDynamicCert(config.TLSDynamicConfig{
		CA: config.TLSDynamicCAConfig{
			SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/proxy/tls.crt", PrivateKeyFile: "../../test/data/proxy/tls.key"},
		},
	}, zap.NewNop())
	require.NoError(t, err)

	minted, err := cert.GetCertificateForHost("10.0.0.5")
	require.NoError(t, err)

	require.Len(t, minted.Leaf.IPAddresses, 1)
	assert.True(t, minted.Leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")))
	assert.Empty(t, minted.Leaf.DNSNames)
}

func TestDynamicCert_GetCertificateForHost_CoversAliases(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		aliases []string
		wantCN  string
		wantDNS []string
		wantIPs []string
	}{
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := NewDynamicCert(config.TLSDynamicConfig{
				CA: config.TLSDynamicCAConfig{
					SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/proxy/tls.crt", PrivateKeyFile: "../../test/data/proxy/tls.key"},
				},
			}, zap.NewNop())
			require.NoError(t, err)

			minted, err := cert.GetCertificateForHost(tt.host, tt.aliases...)
			require.NoError(t, err)

			assert.Equal(t, tt.wantCN, minted.Leaf.Subject.CommonName)
			assert.Equal(t, tt.wantDNS, minted.Leaf.DNSNames)

			var gotIPs []string
			for _, ip := range minted.Leaf.IPAddresses {
				gotIPs = append(gotIPs, ip.String())
			}

			assert.Equal(t, tt.wantIPs, gotIPs)
		})
	}
}

func TestDynamicCert_GetCertificateForHost_CachesPerNameSet(t *testing.T) {
	cert, err := NewDynamicCert(config.TLSDynamicConfig{
		CA: config.TLSDynamicCAConfig{
			SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/proxy/tls.crt", PrivateKeyFile: "../../test/data/proxy/tls.key"},
		},
	}, zap.NewNop())
	require.NoError(t, err)

	first, err := cert.GetCertificateForHost("app.internal", "a.internal")
	require.NoError(t, err)

	// The same host with a different alias set needs its own certificate.
	other, err := cert.GetCertificateForHost("app.internal", "b.internal")
	require.NoError(t, err)
	assert.NotEqual(t, first.Leaf.SerialNumber, other.Leaf.SerialNumber)

	again, err := cert.GetCertificateForHost("app.internal", "a.internal")
	require.NoError(t, err)
	assert.Same(t, first, again)

	// The same aliases in a different order are the same name set.
	sorted, err := cert.GetCertificateForHost("app.internal", "a.internal", "b.internal")
	require.NoError(t, err)

	reordered, err := cert.GetCertificateForHost("app.internal", "b.internal", "a.internal")
	require.NoError(t, err)
	assert.Same(t, sorted, reordered)
}

func TestDynamicCert_GetCertificateForHost_RenewsInsideWindow(t *testing.T) {
	cert, err := NewDynamicCert(config.TLSDynamicConfig{
		CA: config.TLSDynamicCAConfig{
			SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/proxy/tls.crt", PrivateKeyFile: "../../test/data/proxy/tls.key"},
		},
		Cert: config.TLSDynamicCertConfig{
			Duration:    2 * time.Hour,
			RenewBefore: time.Hour,
		},
	}, zap.NewNop())
	require.NoError(t, err)

	first, err := cert.GetCertificateForHost("app.internal")
	require.NoError(t, err)

	// Expire the cached certificate into its renewal window.
	cached, ok := cert.cache.Get("app.internal")
	require.True(t, ok)

	cached.Leaf.NotAfter = time.Now().Add(30 * time.Minute)

	second, err := cert.GetCertificateForHost("app.internal")
	require.NoError(t, err)

	assert.NotEqual(t, first.Leaf.SerialNumber, second.Leaf.SerialNumber)

	// Re-minting replaces the cached entry rather than adding another one.
	assert.Equal(t, 1, cert.cache.Len())
}

// Concurrent cold misses for one host must mint once. This is what the
// re-check inside the lock in GetCertificateForHost buys; without it every
// caller mints its own certificate.
func TestDynamicCert_GetCertificateForHost_ConcurrentColdMissMintsOnce(t *testing.T) {
	const callers = 10

	cert, err := NewDynamicCert(config.TLSDynamicConfig{
		CA: config.TLSDynamicCAConfig{
			SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: "../../test/data/proxy/tls.crt", PrivateKeyFile: "../../test/data/proxy/tls.key"},
		},
	}, zap.NewNop())
	require.NoError(t, err)

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		mintErr error
		serials = map[string]struct{}{}
	)

	start := make(chan struct{})

	for range callers {
		wg.Go(func() {
			<-start

			got, err := cert.GetCertificateForHost("cold.internal")

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				mintErr = err

				return
			}

			serials[got.Leaf.SerialNumber.String()] = struct{}{}
		})
	}

	close(start)
	wg.Wait()

	require.NoError(t, mintErr)
	assert.Len(t, serials, 1, "concurrent cold misses should mint exactly once")
	assert.Equal(t, 1, cert.cache.Len())
}
