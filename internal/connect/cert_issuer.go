// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"gateway/internal/reloader"
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

// certIssuer issues a certificate covering a set of names and runs any
// background maintenance its backend needs.
type certIssuer interface {
	run(ctx context.Context)
	issue(ctx context.Context, names []string) (*tls.Certificate, error)
}

// rotatableIssuer is a certIssuer whose CA can rotate during the process lifetime.
// The channel returned by rotated receives a value after each rotation.
type rotatableIssuer interface {
	rotated() <-chan struct{}
}

func newCertIssuer(cfg config.TLSIssuerConfig, keyCfg keyConfig, ttl time.Duration, logger *zap.Logger) (certIssuer, error) {
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

	reloader *reloader.Reloader
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
	issuer.reloader = reloader.New([]string{cfg.CertificateFile, cfg.PrivateKeyFile}, issuer.load, logger)

	// Load up front so a misconfigured issuer fails at startup.
	if err := issuer.load(); err != nil {
		return nil, err
	}

	return issuer, nil
}

func (l *localIssuer) run(ctx context.Context) {
	l.reloader.Run(ctx)
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

func (l *localIssuer) issue(_ context.Context, names []string) (*tls.Certificate, error) {
	key, err := l.key.generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	l.mu.RLock()
	caCert, caKey := l.caCert, l.caKey
	l.mu.RUnlock()

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    now.Add(-clockSkewBuffer),
		NotAfter:     now.Add(l.ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, caCert, key.Public(), caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign leaf certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{leafDER, caCert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
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

// run logs in to Vault in the background and keeps the token renewed. Unlike
// the SSH CA, login failures retry instead of failing startup: CertManager.Run
// carries no error, so handshakes fail until login succeeds, then self-heal.
func (v *vaultIssuer) run(ctx context.Context) {
	if v.vault.AuthMethod == nil {
		return
	}

	go func() {
		secret := v.vault.LoginWithRetry(ctx)
		if secret == nil {
			return
		}

		v.vault.RunTokenRenewalLoop(ctx, secret)
	}()
}

// issue asks Vault to sign a locally generated key for names through
// <mount>/sign/<role>, so the private key never leaves the Gateway. The context
// is the TLS handshake's, so an abandoned handshake cancels the in-flight request.
func (v *vaultIssuer) issue(ctx context.Context, names []string) (*tls.Certificate, error) {
	key, err := v.key.generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}

	csr, err := certificateRequestPEM(key, names)
	if err != nil {
		return nil, err
	}

	data := map[string]any{
		"csr": csr,
		"ttl": v.ttl.String(),
	}

	// PKI roles restricted to domains reject IP common names outright, so an
	// IP host (the no-SNI local-address fallback) is covered through ip_sans
	// alone; such a role needs require_cn=false.
	if net.ParseIP(names[0]) == nil {
		data["common_name"] = names[0]
	}

	var altNames, ipSANs []string

	for _, name := range names {
		if net.ParseIP(name) != nil {
			ipSANs = append(ipSANs, name)
		} else {
			altNames = append(altNames, name)
		}
	}

	if len(altNames) > 0 {
		data["alt_names"] = strings.Join(altNames, ",")
	}

	if len(ipSANs) > 0 {
		data["ip_sans"] = strings.Join(ipSANs, ",")
	}

	secret, err := v.vault.Client.Logical().WriteWithContext(ctx, v.mount+"/sign/"+v.role, data)
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: empty response", errVaultIssueFailed)
	}

	certPEM, ok := secret.Data["certificate"].(string)
	if !ok || certPEM == "" {
		return nil, fmt.Errorf("%w: no certificate in response", errVaultIssueFailed)
	}

	chain, err := parseCertificateChain(append([]string{certPEM}, caChain(secret.Data)...))
	if err != nil {
		return nil, err
	}

	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse issued certificate: %w", err)
	}

	if err := verifyIssuedCertificate(leaf, key, names); err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// certificateRequestPEM builds a PEM-encoded CSR for key covering names, with
// the requested host as the common name and every name in the SANs.
func certificateRequestPEM(key crypto.Signer, names []string) (string, error) {
	template := &x509.CertificateRequest{}
	if net.ParseIP(names[0]) == nil {
		template.Subject = pkix.Name{CommonName: names[0]}
	}

	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate request: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// verifyIssuedCertificate rejects a CA-issued certificate that is signed by a different signer or
// grants more than the requested asked for.
func verifyIssuedCertificate(leaf *x509.Certificate, key crypto.Signer, names []string) error {
	type publicKey interface {
		Equal(other crypto.PublicKey) bool
	}

	if pub, ok := key.Public().(publicKey); !ok || !pub.Equal(leaf.PublicKey) {
		return fmt.Errorf("%w: certificate public key does not match the Gateway's key", errVaultCertMismatch)
	}

	granted := make(map[string]struct{}, len(leaf.DNSNames)+len(leaf.IPAddresses))
	for _, name := range leaf.DNSNames {
		granted[strings.ToLower(name)] = struct{}{}
	}

	for _, ip := range leaf.IPAddresses {
		granted[ip.String()] = struct{}{}
	}

	requested := make(map[string]struct{}, len(names))

	for _, name := range names {
		// Canonicalize IPs the same way granted names are, so notations match.
		if ip := net.ParseIP(name); ip != nil {
			name = ip.String()
		}

		requested[name] = struct{}{}
	}

	if !maps.Equal(granted, requested) {
		return fmt.Errorf("%w: granted names %q do not match requested %q",
			errVaultCertMismatch, slices.Sorted(maps.Keys(granted)), slices.Sorted(maps.Keys(requested)))
	}

	return nil
}

func parseCertificateChain(pems []string) ([][]byte, error) {
	chain := make([][]byte, 0, len(pems))

	for _, certPEM := range pems {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: response is not PEM certificates", errVaultIssueFailed)
		}

		chain = append(chain, block.Bytes)
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
