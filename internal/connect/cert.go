// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"gateway/internal/config"
)

var (
	errNotCACertificate   = errors.New("certificate is not a certificate authority")
	errCAKeyNotSigner     = errors.New("CA private key does not implement crypto.Signer")
	errUnsupportedKeyType = errors.New("unsupported key type")
	errUnsupportedKeyBits = errors.New("unsupported key bits")
)

// clockSkewGrace backdates minted certificates to tolerate downstream clients
// with slightly-behind clocks.
const clockSkewGrace = 5 * time.Minute

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// Cert mints short-lived leaf certificates signed by the configured CA,
// caching one certificate per requested host and re-minting a fresh one once
// the cached certificate enters the renewal window.
type Cert struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	cert   config.TLSDynamicCertConfig
	logger *zap.Logger

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

func NewCert(cfg config.TLSDynamicConfig, logger *zap.Logger) (*Cert, error) {
	if cfg.CA.SelfSign == nil {
		return nil, config.ErrMissingTLSCAConfig
	}

	pair, err := tls.LoadX509KeyPair(cfg.CA.SelfSign.CertificateFile, cfg.CA.SelfSign.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA key pair: %w", err)
	}

	caCert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	if !caCert.IsCA {
		return nil, errNotCACertificate
	}

	caKey, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errCAKeyNotSigner
	}

	return &Cert{
		caCert: caCert,
		caKey:  caKey,
		cert:   cfg.Cert,
		logger: logger,
		cache:  make(map[string]*tls.Certificate),
	}, nil
}

// GetCertificate implements tls.Config.GetCertificate for handshakes that
// happen before the CONNECT target is known. It mints for the SNI host when
// the client sends one, falling back to the connection's local IP for clients
// that don't (IP-dialed clients and health probes).
func (c *Cert) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		var err error

		host, _, err = net.SplitHostPort(hello.Conn.LocalAddr().String())
		if err != nil {
			return nil, fmt.Errorf("failed to parse local address: %w", err)
		}
	}

	return c.GetCertificateForHost(host)
}

// GetCertificateForHost returns a certificate for the requested host, minting
// a new one when none is cached or the cached one is inside the renewal window.
func (c *Cert) GetCertificateForHost(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if cert, ok := c.cache[host]; ok && time.Now().Before(cert.Leaf.NotAfter.Add(-c.cert.GetRenewBefore())) {
		return cert, nil
	}

	cert, err := c.mint(host)
	if err != nil {
		return nil, err
	}

	c.cache[host] = cert

	return cert, nil
}

func (c *Cert) mint(host string) (*tls.Certificate, error) {
	key, err := c.generateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-clockSkewGrace),
		NotAfter:     now.Add(c.cert.GetDuration()),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, c.caCert, key.Public(), c.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign leaf certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	c.logger.Info("Minted downstream certificate",
		zap.String("host", host),
		zap.Time("not_after", leaf.NotAfter),
	)

	return &tls.Certificate{
		Certificate: [][]byte{leafDER, c.caCert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func (c *Cert) generateKey() (crypto.Signer, error) {
	switch c.cert.GetKeyType() {
	case "ecdsa":
		switch c.cert.GetKeyBits() {
		case 256:
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case 384:
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case 521:
			return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			return nil, fmt.Errorf("%w: ECDSA %d", errUnsupportedKeyBits, c.cert.GetKeyBits())
		}
	case "rsa":
		return rsa.GenerateKey(rand.Reader, c.cert.GetKeyBits())
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedKeyType, c.cert.GetKeyType())
	}
}
