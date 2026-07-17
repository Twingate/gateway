// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	vault "github.com/hashicorp/vault/api"

	gatewayconfig "gateway/internal/config"
)

var (
	errVaultCAFailed       = errors.New("failed to get CA from Vault")
	errVaultSignFailed     = errors.New("failed to sign certificate with Vault")
	errCertPolicyViolation = errors.New("CA-issued certificate violates the requested policy")
)

// ca signs SSH certificates.
type ca interface {
	// PublicKey returns the ca's public key that can verify signed certificates
	publicKey(ctx context.Context) (ssh.PublicKey, error)

	// Sign creates a signed certificate from a request.
	sign(ctx context.Context, req *certificateRequest) (*ssh.Certificate, error)
}

// caConfig contains the CAs needed for SSH authentication operations.
type caConfig struct {
	GatewayHostCA  ca // Signs Gateway's host certificates (presented to clients)
	GatewayUserCA  ca // Signs Gateway's user certificates (presented to upstreams)
	UpstreamHostCA ca // Verifies upstream host certificates (only publicKey is used). If nil, defaults to TOFU verification with upstream's public key.

	vault       *Vault       // Vault client for token lifecycle management (nil for non-Vault CAs)
	keyReloader *keyReloader // Reloads the CA private key on file change (nil for non-manual CAs)
}

// Start begins background CA maintenance: it reloads the manual CA private key on file change.
// For Vault CAs, performs initial Vault authentication and starts the token renewal loop.
// For auto-generated CAs, this is a no-op.
func (c *caConfig) Start(ctx context.Context) error {
	if c.keyReloader != nil {
		c.keyReloader.Run(ctx)
	}

	if c.vault == nil || c.vault.authMethod == nil {
		return nil
	}

	secret, err := c.vault.client.Auth().Login(ctx, c.vault.authMethod)
	if err != nil {
		return fmt.Errorf("failed to login to Vault: %w", err)
	}

	go c.vault.runTokenRenewalLoop(ctx, secret)

	return nil
}

// newCAFromConfig creates CAs based on the provided configuration.
// - If config.Manual is set, creates an embedded CA with the provided key files.
// - If config.Vault is set, creates Vault-backed CAs.
func newCAFromConfig(config gatewayconfig.SSHCAConfig, logger *zap.Logger) (*caConfig, error) {
	switch {
	case config.Manual != nil:
		return newManualCA(config.Manual.PrivateKeyFile, logger)
	case config.Vault != nil:
		return newVaultCA(config.Vault, logger)
	default:
		return nil, gatewayconfig.ErrMissingCAConfig
	}
}

// newManualCA creates an embedded CA with keys loaded from files. The private key is
// reloaded when the file changes, so it can be rotated without a restart.
// The CA signs gateway host and user certificates, and upstream host authentication is verified using TOFU.
func newManualCA(privateKeyFile string, logger *zap.Logger) (*caConfig, error) {
	reloader := newKeyReloader(privateKeyFile, logger)
	if err := reloader.load(); err != nil {
		return nil, err
	}

	ca := &embeddedCA{
		getSigner: reloader.getSigner,
	}

	publicKeyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(reloader.getSigner().PublicKey())))
	logger.Info("Using manual CA for SSH authentication", zap.String("ca_public_key", publicKeyStr))

	return &caConfig{
		GatewayHostCA: ca,
		GatewayUserCA: ca,
		keyReloader:   reloader,
	}, nil
}

// newVaultCA creates Vault-backed CAs.
// Vault config allows setting different CAs for Gateway host and user certificates, and upstream host authentication.
func newVaultCA(vaultConfig *gatewayconfig.SSHCAVaultConfig, logger *zap.Logger) (*caConfig, error) {
	v, err := newVault(vaultConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	gatewayHostCA := &vaultCA{
		client: v.client,
		mount:  vaultConfig.GetGatewayHostCAMount(),
		role:   vaultConfig.GetGatewayHostCARole(),
	}
	gatewayUserCA := &vaultCA{
		client: v.client,
		mount:  vaultConfig.GetGatewayUserCAMount(),
		role:   vaultConfig.GetGatewayUserCARole(),
	}
	upstreamHostCA := &vaultCA{
		client: v.client,
		mount:  vaultConfig.GetUpstreamHostCAMount(),
		role:   "", // No role needed - only used for publicKey retrieval
	}

	return &caConfig{
		GatewayHostCA:  gatewayHostCA,
		GatewayUserCA:  gatewayUserCA,
		UpstreamHostCA: upstreamHostCA,
		vault:          v,
	}, nil
}

func (c *caConfig) upstreamHostKeyCallback(ctx context.Context, upstreamAddress string) (ssh.HostKeyCallback, error) {
	if c.UpstreamHostCA == nil {
		tofuHostKey := newTOFUHostKey(upstreamAddress)

		return tofuHostKey.checkHostKey, nil
	}

	caPublicKey, err := c.UpstreamHostCA.publicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get ca public key: %w", err)
	}

	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return keysEqual(auth, caPublicKey)
		},
	}

	return checker.CheckHostKey, nil
}

const clockSkewBuffer = 30 * time.Second

// embeddedCA signs certificates with a signer held in process. The signer is read
// through a getter on every operation, so it can be swapped by a keyReloader.
type embeddedCA struct {
	getSigner func() ssh.Signer
}

func (ca *embeddedCA) publicKey(_ context.Context) (ssh.PublicKey, error) {
	return ca.getSigner().PublicKey(), nil
}

func (ca *embeddedCA) sign(_ context.Context, req *certificateRequest) (*ssh.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random serial: %w", err)
	}

	keyID := fmt.Sprintf("twingate-%x", sha256.Sum256(req.publicKey.Marshal()))

	now := time.Now()
	cert := &ssh.Certificate{
		Serial:          serial,
		Key:             req.publicKey,
		CertType:        uint32(req.certType),
		ValidPrincipals: req.principals,
		ValidAfter:      mustUint64(now.Add(-clockSkewBuffer)),
		ValidBefore:     mustUint64(now.Add(req.ttl).Add(clockSkewBuffer)),
		KeyId:           keyID,
		Permissions:     req.permissions,
	}

	if err := cert.SignCert(rand.Reader, ca.getSigner()); err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	return cert, nil
}

func randomSerial() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint64(b[:]), nil
}

func mustUint64(t time.Time) uint64 {
	seconds := t.Unix()
	if seconds < 0 {
		panic("negative time is not supported in SSH certificates")
	}

	return uint64(seconds)
}

type vaultCA struct {
	client *vault.Client
	mount  string
	role   string
}

func (ca *vaultCA) publicKey(ctx context.Context) (ssh.PublicKey, error) {
	response, err := ca.client.Logical().ReadWithContext(ctx, ca.mount+"/config/ca")
	if err != nil {
		return nil, err
	}

	if response == nil || response.Data == nil || response.Data["public_key"] == nil {
		return nil, errVaultCAFailed
	}

	publicKeyStr, ok := response.Data["public_key"].(string)
	if !ok || publicKeyStr == "" {
		return nil, errVaultCAFailed
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKeyStr))
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func (ca *vaultCA) sign(ctx context.Context, req *certificateRequest) (*ssh.Certificate, error) {
	data := map[string]any{
		"cert_type":        req.certType.String(),
		"public_key":       string(ssh.MarshalAuthorizedKey(req.publicKey)),
		"valid_principals": strings.Join(req.principals, ","),
		"ttl":              req.ttl.String(),
	}

	if req.certType == UserCert {
		data["extensions"] = req.permissions.Extensions
	}

	response, err := ca.client.SSHWithMountPoint(ca.mount).SignKeyWithContext(ctx, ca.role, data)
	if err != nil {
		return nil, err
	}

	if response == nil || response.Data == nil || response.Data["signed_key"] == nil {
		return nil, errVaultSignFailed
	}

	certStr, ok := response.Data["signed_key"].(string)
	if !ok || certStr == "" {
		return nil, errVaultSignFailed
	}

	cert, err := parseCertificate([]byte(certStr))
	if err != nil {
		return nil, err
	}

	if err := verifyCertificate(cert, req); err != nil {
		return nil, err
	}

	return cert, nil
}

// verifyCertificate rejects a CA-issued certificate that grants more than the request asked for.
func verifyCertificate(cert *ssh.Certificate, req *certificateRequest) error {
	if cert.CertType != uint32(req.certType) {
		return fmt.Errorf("%w: cert type %q does not match requested %q", errCertPolicyViolation, certType(cert.CertType), req.certType)
	}

	if !keysEqual(cert.Key, req.publicKey) {
		return fmt.Errorf("%w: certificate is bound to a different public key", errCertPolicyViolation)
	}

	// Require exact equality: an empty principals list grants every principal, and any extra
	// principal grants access the request never asked for.
	if !maps.Equal(principalSet(cert.ValidPrincipals), principalSet(req.principals)) {
		return fmt.Errorf("%w: granted principals %q do not match requested %q", errCertPolicyViolation, cert.ValidPrincipals, req.principals)
	}

	maxValidBefore := mustUint64(time.Now().Add(req.ttl).Add(clockSkewBuffer))
	if cert.ValidBefore > maxValidBefore {
		return fmt.Errorf("%w: validity %d exceeds requested TTL (max %d)", errCertPolicyViolation, cert.ValidBefore, maxValidBefore)
	}

	// Critical options are restrictions, so dropping one widens privilege; require the
	// cert's options to match the request exactly.
	if !maps.Equal(cert.CriticalOptions, req.permissions.CriticalOptions) {
		return fmt.Errorf("%w: granted critical options %q do not match requested %q", errCertPolicyViolation, cert.CriticalOptions, req.permissions.CriticalOptions)
	}

	// A missing extension only narrows privilege, so reject only unexpected extensions
	// or values.
	for ext, granted := range cert.Extensions {
		requested, ok := req.permissions.Extensions[ext]
		if !ok {
			return fmt.Errorf("%w: unexpected extension %q", errCertPolicyViolation, ext)
		}

		if granted != requested {
			return fmt.Errorf("%w: extension %q granted value %q, requested %q", errCertPolicyViolation, ext, granted, requested)
		}
	}

	return nil
}

func principalSet(principals []string) map[string]struct{} {
	set := make(map[string]struct{}, len(principals))
	for _, p := range principals {
		set[p] = struct{}{}
	}

	return set
}
