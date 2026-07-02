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
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	vault "github.com/hashicorp/vault/api"

	gatewayconfig "gateway/internal/config"
)

var (
	errVaultCAFailed   = errors.New("failed to get CA from Vault")
	errVaultSignFailed = errors.New("failed to sign certificate with Vault")
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

	vault *Vault // Vault client for token lifecycle management (nil for non-Vault CAs)
}

// Start performs initial Vault authentication and starts the token renewal loop.
// For non-Vault CAs, this is a no-op.
func (c *caConfig) Start(ctx context.Context) error {
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
func newCAFromConfig(config *gatewayconfig.SSHCAConfig, logger *zap.Logger) (*caConfig, error) {
	if config != nil && config.Manual != nil {
		return newManualCA(config.Manual.PrivateKeyFile, logger)
	}

	if config != nil && config.Vault != nil {
		return newVaultCA(config.Vault, logger)
	}

	return nil, gatewayconfig.ErrMissingCAConfig
}

// newManualCA creates an embedded CA with keys loaded from files.
// The CA signs gateway host and user certificates, and upstream host authentication is verified using TOFU.
func newManualCA(privateKeyFile string, logger *zap.Logger) (*caConfig, error) {
	privateKey, err := loadPrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}

	ca := &embeddedCA{
		signer: privateKey,
	}

	publicKeyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(privateKey.PublicKey())))
	logger.Info("Using manual CA for SSH authentication", zap.String("ca_public_key", publicKeyStr))

	return &caConfig{
		GatewayHostCA: ca,
		GatewayUserCA: ca,
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

type embeddedCA struct {
	signer ssh.Signer
}

func (ca *embeddedCA) publicKey(_ context.Context) (ssh.PublicKey, error) {
	return ca.signer.PublicKey(), nil
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

	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
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

	return parseCertificate([]byte(certStr))
}
