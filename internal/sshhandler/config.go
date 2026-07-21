// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"gateway/internal/config"
)

var (
	errSSHCertificate      = errors.New("not a valid SSH certificate")
	errTOFUAddressMismatch = errors.New("address does not match known address")
	errTOFUHostKeyMismatch = errors.New("host key does not match known host key")
)

// Default values for SSH configuration.
const (
	defaultHostCertTTL = 24 * time.Hour
	defaultUserCertTTL = 5 * time.Minute
)

const Banner = `

██████████╗██╗    ██╗██╗███╗   ██╗ ██████╗  █████╗ ████████╗███████╗
 ╚══██╔═══╝██║    ██║██║████╗  ██║██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
    ██║    ██║ █╗ ██║██║██╔██╗ ██║██║  ███╗███████║   ██║   █████╗
    ██║    ██║███╗██║██║██║╚██╗██║██║   ██║██╔══██║   ██║   ██╔══╝
    ██║    ╚███╔███╔╝██║██║ ╚████║╚██████╔╝██║  ██║   ██║   ███████╗
    ╚═╝     ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝

################################################################################################
# Welcome! You are now securely connected via Twingate.                                        #
################################################################################################

`

type upstream struct {
	address  string
	username string
}

type Config struct {
	caProvider caProvider

	hostSigner    ssh.Signer
	hostPublicKey ssh.PublicKey
	hostCertTTL   time.Duration

	userSigner    ssh.Signer
	userPublicKey ssh.PublicKey
	userCertTTL   time.Duration

	gatewayUsername string

	auditLog *config.AuditLogConfig
	logger   *zap.Logger
}

// NewConfig creates an SSH handler config from the config package types.
func NewConfig(auditLogConfig *config.AuditLogConfig, sshCfg *config.SSHConfig, logger *zap.Logger) (*Config, error) {
	caProvider, err := newCAFromConfig(sshCfg.CA, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create ca: %w", err)
	}

	keyCfg, err := newKeyConfig(sshCfg.Gateway.Key.Type, sshCfg.Gateway.Key.Bits)
	if err != nil {
		return nil, fmt.Errorf("invalid gateway key config: %w", err)
	}

	hostSigner, hostPublicKey, err := keyCfg.Generate(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate gateway host key: %w", err)
	}

	userSigner, userPublicKey, err := keyCfg.Generate(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate gateway user key: %w", err)
	}

	// Apply defaults for certificate TTLs
	hostCertTTL := sshCfg.Gateway.HostCertificate.TTL
	if hostCertTTL == 0 {
		hostCertTTL = defaultHostCertTTL
	}

	userCertTTL := sshCfg.Gateway.UserCertificate.TTL
	if userCertTTL == 0 {
		userCertTTL = defaultUserCertTTL
	}

	return &Config{
		caProvider:      caProvider,
		hostSigner:      hostSigner,
		hostPublicKey:   hostPublicKey,
		hostCertTTL:     hostCertTTL,
		userSigner:      userSigner,
		userPublicKey:   userPublicKey,
		userCertTTL:     userCertTTL,
		gatewayUsername: sshCfg.Gateway.Username,

		auditLog: auditLogConfig,
		logger:   logger,
	}, nil
}

func (c *Config) GetDownstreamConfig(ctx context.Context) (*ssh.ServerConfig, error) {
	// NoClientAuth accepts the "none" authentication method. PasswordCallback and PublicKeyCallback
	// handle clients that attempt those methods instead. All authentication attempts succeed because
	// authentication is enforced upstream by Twingate.
	downstreamSSHConfig := &ssh.ServerConfig{
		NoClientAuth: true,
		PasswordCallback: func(_ ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
		BannerCallback: func(_ ssh.ConnMetadata) string {
			return Banner
		},
	}

	hostCertRequest := &certificateRequest{
		certType:  ssh.HostCert,
		publicKey: c.hostPublicKey,
		ttl:       c.hostCertTTL,
	}

	hostCertSigner, err := newAutoRenewingCertSigner(ctx, c.caProvider.gatewayHostCA(), hostCertRequest, c.hostSigner, c.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create Gateway's host cert signer: %w", err)
	}

	go func() {
		if err := hostCertSigner.renewalLoop(ctx); err != nil {
			c.logger.Error("failed to renew Gateway's host certificate", zap.Error(err))
		}
	}()

	downstreamSSHConfig.AddHostKey(hostCertSigner)

	return downstreamSSHConfig, nil
}

func (c *Config) GetUpstreamConfig(ctx context.Context, upstream upstream) (*ssh.ClientConfig, error) {
	userCertRequest := &certificateRequest{
		certType:  ssh.UserCert,
		publicKey: c.userPublicKey,
		principals: []string{
			upstream.username,
		},
		ttl: c.userCertTTL,
		permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-port-forwarding": "",
				"permit-pty":             "",
				"permit-user-rc":         "",
			},
		},
	}

	userCert, err := c.caProvider.gatewayUserCA().sign(ctx, userCertRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign user certificate: %w", err)
	}

	userCertSigner, err := ssh.NewCertSigner(userCert, c.userSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create Gateway's user certificate: %w", err)
	}

	hostKeyCallback, err := upstreamHostKeyCallback(ctx, c.caProvider.upstreamHostCA(), upstream.address)
	if err != nil {
		return nil, err
	}

	upstreamSSHConfig := &ssh.ClientConfig{
		User: upstream.username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(userCertSigner),
		},
		HostKeyCallback: hostKeyCallback,
	}

	return upstreamSSHConfig, nil
}

func loadPrivateKey(file string) (ssh.Signer, error) {
	// #nosec G304 -- file paths are from trusted operator configuration
	privateKeyBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %q: %w", file, err)
	}

	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

// parsePublicKey parses a public key from authorized_keys format, which may contain multiple keys.
// It returns only the first key.
func parsePublicKey(publicKeyBytes []byte) (ssh.PublicKey, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return publicKey, nil
}

func parseCertificate(certBytes []byte) (*ssh.Certificate, error) {
	certPublicKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	cert, ok := certPublicKey.(*ssh.Certificate)
	if !ok {
		return nil, errSSHCertificate
	}

	return cert, nil
}

// keysEqual performs constant time comparison of SSH public keys to avoid timing attacks.
func keysEqual(ak, bk ssh.PublicKey) bool {
	// avoid panic if one of the keys is nil, return false instead
	if ak == nil || bk == nil {
		return false
	}

	a := ak.Marshal()
	b := bk.Marshal()

	return subtle.ConstantTimeCompare(a, b) == 1
}

type tofuHostKey struct {
	address string

	once     sync.Once
	knownKey ssh.PublicKey
}

func newTOFUHostKey(address string) *tofuHostKey {
	return &tofuHostKey{
		address: address,
	}
}

func (hk *tofuHostKey) checkHostKey(address string, _ net.Addr, key ssh.PublicKey) error {
	if address != hk.address {
		return errTOFUAddressMismatch
	}

	hk.once.Do(func() {
		hk.knownKey = key
	})

	if keysEqual(hk.knownKey, key) {
		return nil
	}

	return errTOFUHostKeyMismatch
}
