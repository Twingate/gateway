// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cryptotls "crypto/tls"

	"gateway/internal/token"
	"gateway/test/data"
)

func newTLSTestServer(t *testing.T, cert cryptotls.Certificate) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &cryptotls.Config{MinVersion: cryptotls.VersionTLS13, Certificates: []cryptotls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)

	return server
}

func TestNewUpstreamTLSConfig(t *testing.T) {
	cert, err := cryptotls.X509KeyPair(data.ProxyCert, data.ProxyKey)
	require.NoError(t, err)

	server := newTLSTestServer(t, cert)

	trustedPool := x509.NewCertPool()
	require.True(t, trustedPool.AppendCertsFromPEM(data.ProxyCert))

	tests := []struct {
		name       string
		mode       token.TLSClientMode
		rootCAs    *x509.CertPool
		serverName string
		wantErr    bool
	}{
		{name: "verify_full accepts a trusted certificate matching the hostname", mode: token.TLSClientModeVerifyFull, rootCAs: trustedPool, serverName: "localhost"},
		{name: "verify_full rejects a hostname mismatch", mode: token.TLSClientModeVerifyFull, rootCAs: trustedPool, serverName: "corp.internal", wantErr: true},
		{name: "verify_full rejects an untrusted certificate", mode: token.TLSClientModeVerifyFull, rootCAs: x509.NewCertPool(), serverName: "localhost", wantErr: true},
		{name: "verify_ca accepts a hostname mismatch", mode: token.TLSClientModeVerifyCA, rootCAs: trustedPool, serverName: "corp.internal"},
		{name: "verify_ca rejects an untrusted certificate", mode: token.TLSClientModeVerifyCA, rootCAs: x509.NewCertPool(), serverName: "corp.internal", wantErr: true},
		{name: "insecure accepts an untrusted certificate with a hostname mismatch", mode: token.TLSClientModeInsecure, rootCAs: x509.NewCertPool(), serverName: "corp.internal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig := NewUpstreamTLSConfig(tt.mode, tt.rootCAs)
			require.NotNil(t, tlsConfig)
			assert.Equal(t, uint16(cryptotls.VersionTLS13), tlsConfig.MinVersion)

			tlsConfig.ServerName = tt.serverName
			dialer := &cryptotls.Dialer{Config: tlsConfig}

			conn, err := dialer.DialContext(t.Context(), "tcp", server.Listener.Addr().String())
			if tt.wantErr {
				assert.Error(t, err)

				return
			}

			require.NoError(t, err)

			_ = conn.Close()
		})
	}

	t.Run("verify_ca accepts a certificate issued by an intermediate CA", func(t *testing.T) {
		serverCert, rootCAs := newCertificateChain(t)
		chainServer := newTLSTestServer(t, serverCert)

		tlsConfig := NewUpstreamTLSConfig(token.TLSClientModeVerifyCA, rootCAs)
		tlsConfig.ServerName = "corp.internal"
		dialer := &cryptotls.Dialer{Config: tlsConfig}

		conn, err := dialer.DialContext(t.Context(), "tcp", chainServer.Listener.Addr().String())
		require.NoError(t, err)

		_ = conn.Close()
	})

	t.Run("none returns no TLS config", func(t *testing.T) {
		assert.Nil(t, NewUpstreamTLSConfig(token.TLSClientModeNone, trustedPool))
	})
}

// newCertificateChain returns a leaf certificate issued by an intermediate CA, served together with
// that intermediate, and a pool holding only the root CA that issued the intermediate.
func newCertificateChain(t *testing.T) (cryptotls.Certificate, *x509.CertPool) {
	t.Helper()

	issue := func(tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		if parent == nil {
			parent, parentKey = tmpl, key
		}

		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)

		return cert, key
	}

	ca := &x509.Certificate{NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	root, rootKey := issue(ca, nil, nil)
	intermediate, intermediateKey := issue(ca, root, rootKey)
	leaf, leafKey := issue(&x509.Certificate{NotAfter: ca.NotAfter}, intermediate, intermediateKey)

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(root)

	return cryptotls.Certificate{Certificate: [][]byte{leaf.Raw, intermediate.Raw}, PrivateKey: leafKey}, rootCAs
}
