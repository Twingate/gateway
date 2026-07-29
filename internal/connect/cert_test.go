// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

func generateCACert(t *testing.T) tls.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}
}

func newTestCert(t *testing.T, certCfg config.TLSDynamicCertConfig) (*DynamicCert, *x509.CertPool) {
	t.Helper()

	ca := generateCACert(t)
	certFile, keyFile := createCertFiles(t, ca)

	cert, err := NewDynamicCert(config.TLSDynamicConfig{
		CA: config.TLSDynamicCAConfig{
			SelfSign: &config.TLSSelfSignCAConfig{CertificateFile: certFile, PrivateKeyFile: keyFile},
		},
		Cert: certCfg,
	}, zap.NewNop())
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return cert, pool
}

func TestDynamicCert_GetCertificate(t *testing.T) {
	cert, pool := newTestCert(t, config.TLSDynamicCertConfig{})

	minted, err := cert.GetCertificateForHost("app.internal")
	require.NoError(t, err)

	assert.Equal(t, "app.internal", minted.Leaf.Subject.CommonName)
	assert.Equal(t, []string{"app.internal"}, minted.Leaf.DNSNames)
	assert.WithinDuration(t, time.Now().Add(24*time.Hour), minted.Leaf.NotAfter, time.Minute)

	key, ok := minted.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected an ECDSA leaf key by default")
	assert.Equal(t, elliptic.P256(), key.Curve)

	_, err = minted.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "app.internal",
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	assert.NoError(t, err, "leaf should verify against the CA for the requested host")
}

func TestDynamicCert_GetCertificate_IPHost(t *testing.T) {
	cert, _ := newTestCert(t, config.TLSDynamicCertConfig{})

	minted, err := cert.GetCertificateForHost("10.0.0.5")
	require.NoError(t, err)

	require.Len(t, minted.Leaf.IPAddresses, 1)
	assert.True(t, minted.Leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")))
	assert.Empty(t, minted.Leaf.DNSNames)
}

type fakeAddrConn struct {
	net.Conn

	addr net.Addr
}

func (c fakeAddrConn) LocalAddr() net.Addr { return c.addr }

func TestDynamicCert_GetCertificate_ClientHelloSNI(t *testing.T) {
	cert, _ := newTestCert(t, config.TLSDynamicCertConfig{})

	minted, err := cert.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.internal"})
	require.NoError(t, err)

	assert.Equal(t, []string{"app.internal"}, minted.Leaf.DNSNames)
}

func TestDynamicCert_GetCertificate_ClientHelloNoSNIFallsBackToLocalAddr(t *testing.T) {
	cert, _ := newTestCert(t, config.TLSDynamicCertConfig{})

	hello := &tls.ClientHelloInfo{
		Conn: fakeAddrConn{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443}},
	}

	minted, err := cert.GetCertificate(hello)
	require.NoError(t, err)

	require.Len(t, minted.Leaf.IPAddresses, 1)
	assert.True(t, minted.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")))
}

func TestDynamicCert_GetCertificate_UnparsableLocalAddr(t *testing.T) {
	cert, _ := newTestCert(t, config.TLSDynamicCertConfig{})

	hello := &tls.ClientHelloInfo{
		Conn: fakeAddrConn{addr: &net.UnixAddr{Name: "/tmp/gateway.sock", Net: "unix"}},
	}

	_, err := cert.GetCertificate(hello)

	assert.ErrorContains(t, err, "failed to parse local address")
}

func TestDynamicCert_GetCertificate_CachesPerHost(t *testing.T) {
	cert, _ := newTestCert(t, config.TLSDynamicCertConfig{})

	first, err := cert.GetCertificateForHost("app.internal")
	require.NoError(t, err)

	second, err := cert.GetCertificateForHost("app.internal")
	require.NoError(t, err)
	assert.Same(t, first, second)

	other, err := cert.GetCertificateForHost("other.internal")
	require.NoError(t, err)
	assert.NotSame(t, first, other)
}

func TestDynamicCert_GetCertificate_BoundsCacheSize(t *testing.T) {
	cert, _ := newTestCert(t, config.TLSDynamicCertConfig{})
	cert.cache.Resize(3)

	first, err := cert.GetCertificateForHost("first.internal")
	require.NoError(t, err)

	for _, host := range []string{"second.internal", "third.internal", "fourth.internal"} {
		_, err := cert.GetCertificateForHost(host)
		require.NoError(t, err)
	}

	assert.Equal(t, 3, cert.cache.Len(), "cache should stay at the cap")
	assert.False(t, cert.cache.Contains("first.internal"), "the least recently used host should be evicted")

	// The evicted host is re-minted rather than served stale.
	refreshed, err := cert.GetCertificateForHost("first.internal")
	require.NoError(t, err)
	assert.NotEqual(t, first.Leaf.SerialNumber, refreshed.Leaf.SerialNumber)
}

func TestDynamicCert_GetCertificate_EvictsByRecency(t *testing.T) {
	cert, _ := newTestCert(t, config.TLSDynamicCertConfig{})
	cert.cache.Resize(3)

	for _, host := range []string{"first.internal", "second.internal", "third.internal"} {
		_, err := cert.GetCertificateForHost(host)
		require.NoError(t, err)
	}

	// Touching the oldest host makes the next-oldest the eviction candidate.
	touched, err := cert.GetCertificateForHost("first.internal")
	require.NoError(t, err)

	_, err = cert.GetCertificateForHost("fourth.internal")
	require.NoError(t, err)

	assert.False(t, cert.cache.Contains("second.internal"), "the untouched host should be evicted")
	assert.True(t, cert.cache.Contains("first.internal"), "the touched host should survive")

	cached, err := cert.GetCertificateForHost("first.internal")
	require.NoError(t, err)
	assert.Same(t, touched, cached, "the surviving host should still be served from cache")
}

func TestDynamicCert_GetCertificate_RenewFailureKeepsError(t *testing.T) {
	cert, _ := newTestCert(t, config.TLSDynamicCertConfig{
		Duration:    time.Hour,
		RenewBefore: 2 * time.Hour,
	})

	_, err := cert.GetCertificateForHost("app.internal")
	require.NoError(t, err)

	// The cached entry is already inside the renewal window, so the next call
	// re-mints — and now minting fails.
	cert.cert.KeyType = "ed25519"

	_, err = cert.GetCertificateForHost("app.internal")
	assert.ErrorIs(t, err, errUnsupportedKeyType)
}

// Concurrent cold misses for one host must mint once. This is what the
// re-check inside the lock in GetCertificateForHost buys; without it every
// caller mints its own certificate.
func TestDynamicCert_GetCertificate_ConcurrentColdMissMintsOnce(t *testing.T) {
	const callers = 50

	cert, _ := newTestCert(t, config.TLSDynamicCertConfig{})

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

func TestDynamicCert_GetCertificate_RenewsInsideWindow(t *testing.T) {
	// renewBefore longer than duration puts a freshly minted certificate
	// inside the renewal window immediately, forcing a re-mint on every call.
	cert, _ := newTestCert(t, config.TLSDynamicCertConfig{
		Duration:    time.Hour,
		RenewBefore: 2 * time.Hour,
	})

	first, err := cert.GetCertificateForHost("app.internal")
	require.NoError(t, err)

	second, err := cert.GetCertificateForHost("app.internal")
	require.NoError(t, err)

	assert.NotSame(t, first, second)
	assert.NotEqual(t, first.Leaf.SerialNumber, second.Leaf.SerialNumber)

	// Re-minting replaces the cached entry rather than adding another one.
	assert.Equal(t, 1, cert.cache.Len())
}

func TestDynamicCert_GetCertificate_RSAKey(t *testing.T) {
	cert, _ := newTestCert(t, config.TLSDynamicCertConfig{KeyType: "rsa", KeyBits: 2048})

	minted, err := cert.GetCertificateForHost("app.internal")
	require.NoError(t, err)

	_, ok := minted.PrivateKey.(*rsa.PrivateKey)
	assert.True(t, ok, "expected an RSA leaf key")
}

func TestDynamicCert_GetCertificate_UnsupportedKeyConfig(t *testing.T) {
	tests := []struct {
		name    string
		certCfg config.TLSDynamicCertConfig
		wantErr error
	}{
		{
			name:    "unsupported key type",
			certCfg: config.TLSDynamicCertConfig{KeyType: "ed25519"},
			wantErr: errUnsupportedKeyType,
		},
		{
			name:    "unsupported ecdsa key bits",
			certCfg: config.TLSDynamicCertConfig{KeyType: "ecdsa", KeyBits: 512},
			wantErr: errUnsupportedKeyBits,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, _ := newTestCert(t, tt.certCfg)

			_, err := cert.GetCertificateForHost("app.internal")
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestNewDynamicCert_ProxyFixture guards the test/data/proxy fixture staying a CA
// certificate — tools/local uses it as the dynamic signing CA.
func TestNewDynamicCert_ProxyFixture(t *testing.T) {
	cert, err := NewDynamicCert(config.TLSDynamicConfig{
		CA: config.TLSDynamicCAConfig{
			SelfSign: &config.TLSSelfSignCAConfig{
				CertificateFile: "../../test/data/proxy/tls.crt",
				PrivateKeyFile:  "../../test/data/proxy/tls.key",
			},
		},
	}, zap.NewNop())
	require.NoError(t, err)

	minted, err := cert.GetCertificateForHost("127.0.0.1")
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(data.ProxyCert)

	_, err = minted.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "127.0.0.1",
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	assert.NoError(t, err, "minted leaf should verify against the proxy fixture CA")
}

func TestNewDynamicCert_Errors(t *testing.T) {
	caFile, _ := createCertFiles(t, generateCACert(t))
	nonCAFile, nonCAKeyFile := createCertFiles(t, generateCert(t))
	_, otherKeyFile := createCertFiles(t, generateCACert(t))

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
			selfSign:    &config.TLSSelfSignCAConfig{CertificateFile: caFile, PrivateKeyFile: otherKeyFile},
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
