// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"gateway/internal/config"
	filereloader "gateway/internal/reloader"
	"gateway/internal/vault"
)

const clockSkewBuffer = 30 * time.Second

var (
	errNotCACertificate  = errors.New("certificate is not a certificate authority")
	errCAKeyNotSigner    = errors.New("CA private key does not implement crypto.Signer")
	errVaultIssueFailed  = errors.New("failed to issue certificate with Vault")
	errVaultCertMismatch = errors.New("certificate issued by Vault does not match the request")
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// issuer issues the certificate served on a handshake, signs certificate requests
// with its CA and runs any background maintenance its backend needs.
type issuer interface {
	run(ctx context.Context) error
	issue(ctx context.Context, name string) (*tls.Certificate, error)
	sign(ctx context.Context, csr *x509.CertificateRequest) (leaf *x509.Certificate, caChain []*x509.Certificate, err error)
}

// rotatableIssuer is an issuer whose CA can rotate during the process lifetime.
// The channel returned by rotated receives a value after each rotation.
type rotatableIssuer interface {
	rotated() <-chan struct{}
}

func newIssuer(cfg config.TLSIssuerConfig, keyCfg keyConfig, ttl time.Duration, logger *zap.Logger) (issuer, error) {
	switch {
	case cfg.Local != nil:
		return newLocalIssuer(cfg.Local, keyCfg, ttl, logger)
	case cfg.Vault != nil:
		return newVaultIssuer(cfg.Vault, keyCfg, ttl, logger)
	default:
		return nil, config.ErrMissingTLSIssuerConfig
	}
}

// localIssuer signs certificates locally with a CA loaded from files, reloading
// them on change so the CA can be rotated without a restart.
type localIssuer struct {
	certFile string
	keyFile  string
	key      keyConfig
	ttl      time.Duration
	logger   *zap.Logger

	rotateCh chan struct{} // Receives a value after each CA rotation (implements rotatableIssuer)

	mu     sync.RWMutex
	caCert *x509.Certificate
	caKey  crypto.Signer

	reloader *filereloader.Reloader
}

func newLocalIssuer(cfg *config.TLSLocalIssuerConfig, keyCfg keyConfig, ttl time.Duration, logger *zap.Logger) (*localIssuer, error) {
	issuer := &localIssuer{
		certFile: cfg.CertificateFile,
		keyFile:  cfg.PrivateKeyFile,
		key:      keyCfg,
		ttl:      ttl,
		logger:   logger,
		rotateCh: make(chan struct{}, 1),
	}
	issuer.reloader = filereloader.New([]string{cfg.CertificateFile, cfg.PrivateKeyFile}, issuer.load, logger)

	// Load up front so a misconfigured issuer fails at startup.
	if err := issuer.load(); err != nil {
		return nil, err
	}

	return issuer, nil
}

func (l *localIssuer) run(ctx context.Context) error {
	l.reloader.Run(ctx)

	return nil
}

func (l *localIssuer) rotated() <-chan struct{} {
	return l.rotateCh
}

func (l *localIssuer) load() error {
	pair, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
	if err != nil {
		return fmt.Errorf("failed to load CA key pair: %w", err)
	}

	caCert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	if !caCert.IsCA {
		return fmt.Errorf("%w: %q", errNotCACertificate, l.certFile)
	}

	caKey, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("%w: %q", errCAKeyNotSigner, l.keyFile)
	}

	l.mu.Lock()
	previous := l.caCert
	l.caCert = caCert
	l.caKey = caKey
	l.mu.Unlock()

	// The reloader loads again when it starts watching, so only a different CA
	// counts as a rotation.
	if previous == nil || bytes.Equal(previous.Raw, caCert.Raw) {
		return nil
	}

	l.logger.Info("Reloaded CA certificate and key files", zap.String("certificateFile", l.certFile))

	// Non-blocking send: a pending notification already covers the latest CA.
	select {
	case l.rotateCh <- struct{}{}:
	default:
	}

	return nil
}

func (l *localIssuer) issue(ctx context.Context, name string) (*tls.Certificate, error) {
	return issueCertificate(ctx, l, l.key, name)
}

func (l *localIssuer) sign(_ context.Context, csr *x509.CertificateRequest) (*x509.Certificate, []*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	l.mu.RLock()
	caCert, caKey := l.caCert, l.caKey
	l.mu.RUnlock()

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-clockSkewBuffer),
		NotAfter:     now.Add(l.ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign leaf certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	return leaf, []*x509.Certificate{caCert}, nil
}

// issueCertificate generates a leaf key and has the issuer's CA sign a request
// covering name, assembling the certificate served on the handshake.
func issueCertificate(ctx context.Context, i issuer, keyCfg keyConfig, name string) (*tls.Certificate, error) {
	key, err := keyCfg.generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}

	csr, err := certificateRequest(key, name)
	if err != nil {
		return nil, err
	}

	leaf, caChain, err := i.sign(ctx, csr)
	if err != nil {
		return nil, err
	}

	chain := make([][]byte, 0, len(caChain)+1)
	chain = append(chain, leaf.Raw)

	for _, ca := range caChain {
		chain = append(chain, ca.Raw)
	}

	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// certificateRequest builds a certificate request covering name, signed by key so a
// backend can forward it to a remote CA.
func certificateRequest(key crypto.Signer, name string) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{}

	// A handshake without SNI leaves no name, and the certificate then covers none.
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else if name != "" {
		template.DNSNames = []string{name}
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}

	return csr, nil
}

// vaultIssuer issues leaf certificates through Vault's PKI secrets engine.
type vaultIssuer struct {
	vault *vault.Vault
	mount string
	role  string
	key   keyConfig
	ttl   time.Duration
}

func newVaultIssuer(cfg *config.TLSVaultIssuerConfig, keyCfg keyConfig, ttl time.Duration, logger *zap.Logger) (*vaultIssuer, error) {
	v, err := vault.New(cfg.VaultConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	return &vaultIssuer{vault: v, mount: cfg.GetMount(), role: cfg.Role, key: keyCfg, ttl: ttl}, nil
}

// run logs in to Vault and keeps the token renewed in the background.
func (v *vaultIssuer) run(ctx context.Context) error {
	if v.vault.AuthMethod == nil {
		return nil
	}

	secret, err := v.vault.Client.Auth().Login(ctx, v.vault.AuthMethod)
	if err != nil {
		return fmt.Errorf("failed to login to Vault: %w", err)
	}

	go v.vault.RunTokenRenewalLoop(ctx, secret)

	return nil
}

func (v *vaultIssuer) issue(ctx context.Context, name string) (*tls.Certificate, error) {
	return issueCertificate(ctx, v, v.key, name)
}

// sign has Vault sign the request through <mount>/sign/<role>, so the private key
// never leaves the Gateway. The context is the TLS handshake's, so an abandoned
// handshake cancels the in-flight request.
func (v *vaultIssuer) sign(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, []*x509.Certificate, error) {
	data := map[string]any{
		"csr":         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})),
		"common_name": commonName(csr),
		"ttl":         v.ttl.String(),
	}

	if len(csr.DNSNames) > 0 {
		data["alt_names"] = strings.Join(csr.DNSNames, ",")
	}

	if len(csr.IPAddresses) > 0 {
		ipSANs := make([]string, 0, len(csr.IPAddresses))
		for _, ip := range csr.IPAddresses {
			ipSANs = append(ipSANs, ip.String())
		}

		data["ip_sans"] = strings.Join(ipSANs, ",")
	}

	secret, err := v.vault.Client.Logical().WriteWithContext(ctx, v.mount+"/sign/"+v.role, data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, nil, fmt.Errorf("%w: empty response", errVaultIssueFailed)
	}

	certPEM, ok := secret.Data["certificate"].(string)
	if !ok || certPEM == "" {
		return nil, nil, fmt.Errorf("%w: no certificate in response", errVaultIssueFailed)
	}

	chain, err := parseCertificateChain(append([]string{certPEM}, caChain(secret.Data)...))
	if err != nil {
		return nil, nil, err
	}

	leaf := chain[0]
	if err := verifyIssuedCertificate(leaf, csr, v.ttl); err != nil {
		return nil, nil, err
	}

	return leaf, chain[1:], nil
}

// commonName returns the request's name for Vault's common_name field. A handshake
// without SNI leaves it empty, which a PKI role only accepts with require_cn=false.
func commonName(csr *x509.CertificateRequest) string {
	if len(csr.DNSNames) > 0 {
		return csr.DNSNames[0]
	}

	if len(csr.IPAddresses) > 0 {
		return csr.IPAddresses[0].String()
	}

	return ""
}

// verifyIssuedCertificate rejects a CA-issued certificate that is signed by a different signer or
// grants more than the request asked for, in names or in validity.
func verifyIssuedCertificate(leaf *x509.Certificate, csr *x509.CertificateRequest, ttl time.Duration) error {
	type publicKey interface {
		Equal(other crypto.PublicKey) bool
	}

	if pub, ok := csr.PublicKey.(publicKey); !ok || !pub.Equal(leaf.PublicKey) {
		return fmt.Errorf("%w: certificate public key does not match the Gateway's key", errVaultCertMismatch)
	}

	granted := certificateNames(leaf.DNSNames, leaf.IPAddresses)
	requested := certificateNames(csr.DNSNames, csr.IPAddresses)

	if !maps.Equal(granted, requested) {
		return fmt.Errorf("%w: granted names %q do not match requested %q",
			errVaultCertMismatch, slices.Sorted(maps.Keys(granted)), slices.Sorted(maps.Keys(requested)))
	}

	maxNotAfter := time.Now().Add(ttl).Add(clockSkewBuffer)
	if leaf.NotAfter.After(maxNotAfter) {
		return fmt.Errorf("%w: validity %s exceeds requested TTL (max %s)", errVaultCertMismatch, leaf.NotAfter, maxNotAfter)
	}

	return nil
}

// certificateNames returns the names as a set, lowercased and in canonical IP
// notation so both sides of a comparison match.
func certificateNames(dnsNames []string, ips []net.IP) map[string]struct{} {
	names := make(map[string]struct{}, len(dnsNames)+len(ips))

	for _, name := range dnsNames {
		names[strings.ToLower(name)] = struct{}{}
	}

	for _, ip := range ips {
		names[ip.String()] = struct{}{}
	}

	return names
}

// parseCertificateChain parses the PEM certificates in a CA's response, leaf first.
func parseCertificateChain(pems []string) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(pems))

	for _, certPEM := range pems {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: response is not PEM certificates", errVaultIssueFailed)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse issued certificate: %w", err)
		}

		chain = append(chain, cert)
	}

	return chain, nil
}

// caChain returns the CA chain PEMs from the response, falling back to the
// issuing CA when the chain is absent.
func caChain(data map[string]any) []string {
	if chain, ok := data["ca_chain"].([]any); ok {
		cas := make([]string, 0, len(chain))

		for _, ca := range chain {
			if caPEM, ok := ca.(string); ok && caPEM != "" {
				cas = append(cas, caPEM)
			}
		}

		if len(cas) > 0 {
			return cas
		}
	}

	if issuingCA, ok := data["issuing_ca"].(string); ok && issuingCA != "" {
		return []string{issuingCA}
	}

	return nil
}
