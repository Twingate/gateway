// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	vault "github.com/hashicorp/vault/api"

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

// issueTestCertificate returns leaf, key, and CA PEMs shaped like a Vault PKI
// issue response covering names.
func issueTestCertificate(t *testing.T, names []string) (certPEM, keyPEM, caPEM string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			leafTemplate.IPAddresses = append(leafTemplate.IPAddresses, ip)
		} else {
			leafTemplate.DNSNames = append(leafTemplate.DNSNames, name)
		}
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	return certPEM, keyPEM, caPEM
}

// newTestVaultIssuer returns a vaultIssuer whose client talks to a test server
// running handler.
func newTestVaultIssuer(t *testing.T, handler http.HandlerFunc) *vaultIssuer {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	apiConfig := vault.DefaultConfig()
	apiConfig.Address = server.URL
	apiConfig.MaxRetries = 0 // Fail fast on error responses instead of retrying with backoff.

	client, err := vault.NewClient(apiConfig)
	require.NoError(t, err)
	client.SetToken("test-token")

	return &vaultIssuer{
		vault: &Vault{client: client, logger: zap.NewNop()},
		mount: "pki",
		role:  "test-role",
	}
}

func TestVaultIssuer_Issue(t *testing.T) {
	names := []string{"10.0.0.1", "a.example.com", "b.example.com"}
	certPEM, keyPEM, caPEM := issueTestCertificate(t, names)

	issuer := newTestVaultIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/pki/issue/test-role", r.URL.Path)

		var payload map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		assert.Equal(t, "10.0.0.1", payload["common_name"])
		assert.Equal(t, "a.example.com,b.example.com", payload["alt_names"])
		assert.Equal(t, "10.0.0.1", payload["ip_sans"])
		assert.Equal(t, "24h0m0s", payload["ttl"])

		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"certificate": certPEM,
			"private_key": keyPEM,
			"ca_chain":    []string{caPEM},
		}})
	})

	cert, err := issuer.issue(names)
	require.NoError(t, err)
	require.NotNil(t, cert.Leaf)
	assert.Equal(t, []string{"a.example.com", "b.example.com"}, cert.Leaf.DNSNames)
	assert.Len(t, cert.Certificate, 2)
}

func TestVaultIssuer_Issue_IssuingCAFallback(t *testing.T) {
	certPEM, keyPEM, caPEM := issueTestCertificate(t, []string{"app.example.com"})

	issuer := newTestVaultIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"certificate": certPEM,
			"private_key": keyPEM,
			"issuing_ca":  caPEM,
		}})
	})

	cert, err := issuer.issue([]string{"app.example.com"})
	require.NoError(t, err)
	assert.Len(t, cert.Certificate, 2)
}

func TestVaultIssuer_Issue_Error(t *testing.T) {
	certPEM, keyPEM, _ := issueTestCertificate(t, []string{"app.example.com"})

	tests := []struct {
		name         string
		responseData map[string]any // nil sends {"data": null}
		wantErr      error
	}{
		{name: "null data", responseData: nil, wantErr: errVaultIssueFailed},
		{name: "missing certificate", responseData: map[string]any{"private_key": keyPEM}, wantErr: errVaultIssueFailed},
		{name: "empty certificate", responseData: map[string]any{"certificate": "", "private_key": keyPEM}, wantErr: errVaultIssueFailed},
		{name: "missing private key", responseData: map[string]any{"certificate": certPEM}, wantErr: errVaultIssueFailed},
		{name: "unparseable certificate", responseData: map[string]any{"certificate": "garbage", "private_key": keyPEM}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := newTestVaultIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": tt.responseData})
			})

			_, err := issuer.issue([]string{"app.example.com"})
			require.Error(t, err)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestVaultIssuer_Issue_RequestFails(t *testing.T) {
	issuer := newTestVaultIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := issuer.issue([]string{"app.example.com"})
	require.Error(t, err)
	assert.NotErrorIs(t, err, errVaultIssueFailed)
}

func TestVaultIssuer_Run_LoginsInBackground(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		secret := vaultAuthSecret("login-token", 60)
		issuer := &vaultIssuer{vault: newTestVault(t, &mockAuthMethod{secret: secret})}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		issuer.run(ctx)
		synctest.Wait()

		assert.Equal(t, "login-token", issuer.vault.client.Token())
	})
}

func TestVaultIssuer_Run_NoAuthMethod(t *testing.T) {
	issuer := &vaultIssuer{vault: newTestVault(t, nil)}

	issuer.run(t.Context())

	assert.Equal(t, "initial-token", issuer.vault.client.Token())
}

func TestNewDynamicCert_Vault(t *testing.T) {
	cfg := config.TLSDynamicConfig{CA: config.TLSDynamicCAConfig{Vault: &config.TLSVaultCAConfig{
		Address: "https://vault.example.com:8200",
		Role:    "gateway",
	}}}

	cert, err := NewDynamicCert(cfg, zap.NewNop())
	require.NoError(t, err)
	assert.IsType(t, &vaultIssuer{}, cert.issuer)
}
