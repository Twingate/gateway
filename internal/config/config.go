// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
	"go.yaml.in/yaml/v4"
	"golang.org/x/crypto/ssh"
)

var (
	ErrRequired          = errors.New("required field is missing")
	ErrInvalidPort       = errors.New("invalid port number")
	ErrDuplicateUpstream = errors.New("duplicate upstream name")
	ErrInvalidSSHKeyType = errors.New("invalid SSH key type")
	ErrNegativeTTL       = errors.New("TTL must be non-negative")
)

var issuerByDomain = map[string]string{
	"test":          "twingate-local",
	"dev.opstg.com": "twingate-dev",
	"stg.opstg.com": "twingate-stg",
	"sec.opstg.com": "twingate-sec",
	"twingate.com":  "twingate",
}

const (
	defaultTwingateHost               = "twingate.com"
	defaultPort                       = 8443
	defaultMetricsPort                = 9090
	defaultAuditLogFlushInterval      = time.Minute * 10
	defaultAuditLogFlushSizeThreshold = 1_000_000 // 1MB in bytes
)

type Config struct {
	Twingate    TwingateConfig    `yaml:"twingate"`
	Port        int               `yaml:"port"`
	MetricsPort int               `yaml:"metricsPort"`
	AuditLog    AuditLogConfig    `yaml:"auditLog"`
	TLS         TLSConfig         `yaml:"tls"`
	Kubernetes  *KubernetesConfig `yaml:"kubernetes,omitempty"`
	SSH         *SSHConfig        `yaml:"ssh,omitempty"`
	WebApp      *WebAppConfig     `yaml:"webApp,omitempty"`
}

type WebAppConfig struct {
	Headers map[string]string `yaml:"headers,omitempty"`
}

type TwingateConfig struct {
	Network string `yaml:"network"`
	Host    string `yaml:"host"`
}

// JWKSURL returns the controller endpoint for fetching GAT signing keys.
func (t TwingateConfig) JWKSURL() string {
	return fmt.Sprintf("https://%s.%s/api/v1/jwk/ec", t.Network, t.Host)
}

// Issuer returns the expected JWT issuer for the configured controller host.
func (t TwingateConfig) Issuer() string {
	return issuerByDomain[trustedDomainFor(t.Host)]
}

type AuditLogConfig struct {
	FlushInterval      time.Duration `yaml:"flushInterval"`
	FlushSizeThreshold int           `yaml:"flushSizeThreshold"` // bytes
}

type TLSConfig struct {
	CertificateFile string `yaml:"certificateFile"`
	PrivateKeyFile  string `yaml:"privateKeyFile"`
}

type KubernetesConfig struct {
	Upstreams []KubernetesUpstream `yaml:"upstreams"`
}

type KubernetesUpstream struct {
	Name            string `yaml:"name"`
	BearerToken     string `yaml:"bearerToken,omitempty"`
	BearerTokenFile string `yaml:"bearerTokenFile,omitempty"`
	CAFile          string `yaml:"caFile,omitempty"`
}

type SSHConfig struct {
	Gateway SSHGatewayConfig `yaml:"gateway"`
	CA      SSHCAConfig      `yaml:"ca"`
}

type SSHGatewayConfig struct {
	Username        string               `yaml:"username"` // username for upstream connections
	Key             SSHKeyConfig         `yaml:"key"`
	HostCertificate SSHCertificateConfig `yaml:"hostCertificate"`
	UserCertificate SSHCertificateConfig `yaml:"userCertificate"`
}

type SSHKeyConfig struct {
	Type string `yaml:"type"` // ed25519, ecdsa, rsa or SSH key type identifiers e.g. ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521. Defaults to ed25519
	Bits int    `yaml:"bits"` // ECDSA: 256/384/521, RSA: 2048/3072/4096. Defaults to 256 for ECDSA, 2048 for RSA.
}

type SSHCertificateConfig struct {
	TTL time.Duration `yaml:"ttl"`
}

// SSHCAConfig represents the CA configuration. Only one of Manual or Vault should be set.
// If neither is set, auto-generated CA is used.
type SSHCAConfig struct {
	Manual *SSHCAManualConfig `yaml:"manual,omitempty"`
	Vault  *SSHCAVaultConfig  `yaml:"vault,omitempty"`
}

type SSHCAManualConfig struct {
	PrivateKeyFile string `yaml:"privateKeyFile"`
}

type SSHCAVaultConfig struct {
	Address      string               `yaml:"address"`
	CABundleFile string               `yaml:"caBundleFile,omitempty"`
	Auth         SSHCAVaultAuthConfig `yaml:"auth"`

	Namespace string `yaml:"namespace,omitempty"` // Optional Vault namespace

	// Default mount point and role (used for all CAs unless overridden below)
	Mount string `yaml:"mount,omitempty"`
	Role  string `yaml:"role,omitempty"`

	// Optional overrides for advanced setups with separate CAs
	GatewayHostCA  *SSHCAVaultCertConfig  `yaml:"gatewayHostCA,omitempty"`  // CA for signing Gateway's host certificates (presented to clients)
	GatewayUserCA  *SSHCAVaultCertConfig  `yaml:"gatewayUserCA,omitempty"`  // CA for signing Gateway's user certificates (presented to upstreams)
	UpstreamHostCA *SSHCAVaultMountConfig `yaml:"upstreamHostCA,omitempty"` // CA for verifying upstreams' host certificates (no role needed)
}

// SSHCAVaultCertConfig allows overriding the default mount/role for certificate signing.
type SSHCAVaultCertConfig struct {
	Mount string `yaml:"mount,omitempty"`
	Role  string `yaml:"role,omitempty"`
}

// SSHCAVaultMountConfig allows overriding the mount for CA public key retrieval (no role needed).
type SSHCAVaultMountConfig struct {
	Mount string `yaml:"mount,omitempty"`
}

type SSHCAVaultAuthConfig struct {
	Token   string                   `yaml:"token,omitempty"`
	AppRole *SSHCAVaultAppRoleConfig `yaml:"appRole,omitempty"`
	GCP     *SSHCAVaultGCPConfig     `yaml:"gcp,omitempty"`
	AWS     *SSHCAVaultAWSConfig     `yaml:"aws,omitempty"`
}

type SSHCAVaultAppRoleConfig struct {
	Mount        string `yaml:"mount,omitempty"`
	RoleID       string `yaml:"roleID"`
	SecretID     string `yaml:"secretID"`
	SecretIDFile string `yaml:"secretIDFile"`
}

type SSHCAVaultGCPConfig struct {
	Mount               string `yaml:"mount,omitempty"`
	Role                string `yaml:"role"`
	Type                string `yaml:"type"`
	ServiceAccountEmail string `yaml:"serviceAccountEmail,omitempty"` // Required for iam type
}

type SSHCAVaultAWSConfig struct {
	Mount             string `yaml:"mount,omitempty"`
	Role              string `yaml:"role"`
	Type              string `yaml:"type"`
	Region            string `yaml:"region,omitempty"`
	IAMServerIDHeader string `yaml:"iamServerIDHeader,omitempty"`
	// EC2-only options
	SignatureType string `yaml:"signatureType,omitempty"`
	Nonce         string `yaml:"nonce,omitempty"`
}

func newDefaultConfig() *Config {
	return &Config{
		Port:        defaultPort,
		MetricsPort: defaultMetricsPort,
		Twingate: TwingateConfig{
			Host: defaultTwingateHost,
		},
		AuditLog: AuditLogConfig{
			FlushInterval:      defaultAuditLogFlushInterval,
			FlushSizeThreshold: defaultAuditLogFlushSizeThreshold,
		},
	}
}

func Load(path string) (*Config, error) {
	// #nosec G304 -- file path is from trusted operator configuration
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := newDefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

func stripNetworkPrefix(hostname, network string) string {
	return strings.TrimPrefix(hostname, network+".")
}

func resolveTwingateHostname(targetURL, defaultHost string, retryMax int, logger *zap.Logger) string {
	logger = logger.With(zap.String("url", targetURL), zap.String("defaultHost", defaultHost))

	client := retryablehttp.NewClient()
	client.HTTPClient.Timeout = 1 * time.Second
	client.HTTPClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client.RetryMax = retryMax
	client.Logger = nil

	resp, err := client.Head(targetURL)
	if err != nil {
		logger.Warn("Failed to resolve Twingate hostname", zap.Error(err))

		return defaultHost
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPermanentRedirect {
		logger.Warn("No redirect received", zap.Int("statusCode", resp.StatusCode))

		return defaultHost
	}

	location, err := resp.Location()
	if err != nil {
		logger.Warn("Failed to parse redirect location", zap.Error(err))

		return defaultHost
	}

	resolved := location.Hostname()
	logger.Info("Resolved Twingate hostname", zap.String("hostname", resolved))

	return resolved
}

func (c *Config) ResolveTwingateHost(logger *zap.Logger) {
	resolvedHostname := resolveTwingateHostname(c.Twingate.JWKSURL(), c.Twingate.Host, 2, logger)

	c.Twingate.Host = stripNetworkPrefix(resolvedHostname, c.Twingate.Network)
}

func (c *Config) Validate() error {
	if c.Twingate.Network == "" {
		return fmt.Errorf("%w: twingate.network", ErrRequired)
	}

	if err := validatePort(c.Port, "port"); err != nil {
		return err
	}

	if err := validatePort(c.MetricsPort, "metricsPort"); err != nil {
		return err
	}

	if err := c.TLS.Validate(); err != nil {
		return fmt.Errorf("tls config: %w", err)
	}

	if c.Kubernetes != nil {
		if err := c.Kubernetes.Validate(); err != nil {
			return fmt.Errorf("kubernetes config: %w", err)
		}
	}

	if c.SSH != nil {
		if err := c.SSH.Validate(); err != nil {
			return fmt.Errorf("ssh config: %w", err)
		}
	}

	// Check that at least one protocol is configured
	if c.Kubernetes == nil && c.SSH == nil && c.WebApp == nil {
		return fmt.Errorf("%w: at least one protocol (Kubernetes, SSH, or WebApp) must be configured", ErrRequired)
	}

	return nil
}

func (t *TLSConfig) Validate() error {
	if t.CertificateFile == "" {
		return fmt.Errorf("%w: certificateFile", ErrRequired)
	}

	if t.PrivateKeyFile == "" {
		return fmt.Errorf("%w: privateKeyFile", ErrRequired)
	}

	return nil
}

func (k *KubernetesConfig) Validate() error {
	upstreamNames := make(map[string]struct{})

	for i, upstream := range k.Upstreams {
		if err := upstream.Validate(); err != nil {
			return fmt.Errorf("upstreams[%d] (name: %q): %w", i, upstream.Name, err)
		}

		if _, exists := upstreamNames[upstream.Name]; exists {
			return fmt.Errorf("%w: %q", ErrDuplicateUpstream, upstream.Name)
		}

		upstreamNames[upstream.Name] = struct{}{}
	}

	return nil
}

func (k *KubernetesUpstream) Validate() error {
	if k.Name == "" {
		return fmt.Errorf("%w: name", ErrRequired)
	}

	if k.BearerToken == "" && k.BearerTokenFile == "" {
		return fmt.Errorf("%w: either bearerToken or bearerTokenFile is required", ErrRequired)
	}

	return nil
}

func (s *SSHConfig) Validate() error {
	if err := s.Gateway.Validate(); err != nil {
		return fmt.Errorf("gateway: %w", err)
	}

	if err := s.CA.Validate(); err != nil {
		return fmt.Errorf("ca: %w", err)
	}

	return nil
}

func (g *SSHGatewayConfig) Validate() error {
	if g.Username == "" {
		return fmt.Errorf("%w: username", ErrRequired)
	}

	if err := g.Key.Validate(); err != nil {
		return fmt.Errorf("key: %w", err)
	}

	if err := g.HostCertificate.Validate(); err != nil {
		return fmt.Errorf("hostCertificate: %w", err)
	}

	if err := g.UserCertificate.Validate(); err != nil {
		return fmt.Errorf("userCertificate: %w", err)
	}

	return nil
}

func (k *SSHKeyConfig) Validate() error {
	validTypes := map[string]bool{
		"ed25519":           true,
		"ecdsa":             true,
		"rsa":               true,
		ssh.KeyAlgoED25519:  true,
		ssh.KeyAlgoECDSA256: true,
		ssh.KeyAlgoECDSA384: true,
		ssh.KeyAlgoECDSA521: true,
		ssh.KeyAlgoRSA:      true,
	}

	if k.Type != "" && !validTypes[k.Type] {
		return ErrInvalidSSHKeyType
	}

	return nil
}

func (c *SSHCertificateConfig) Validate() error {
	if c.TTL < 0 {
		return ErrNegativeTTL
	}

	return nil
}

var ErrConflictingCAConfig = errors.New("only one of 'manual' or 'vault' can be specified for CA config")

func (c *SSHCAConfig) Validate() error {
	if c.Manual != nil && c.Vault != nil {
		return ErrConflictingCAConfig
	}

	if c.Manual != nil {
		if err := c.Manual.Validate(); err != nil {
			return fmt.Errorf("manual: %w", err)
		}
	}

	if c.Vault != nil {
		if err := c.Vault.Validate(); err != nil {
			return fmt.Errorf("vault: %w", err)
		}
	}

	return nil
}

func (m *SSHCAManualConfig) Validate() error {
	if m.PrivateKeyFile == "" {
		return fmt.Errorf("%w: privateKeyFile", ErrRequired)
	}

	return nil
}

func (v *SSHCAVaultConfig) Validate() error {
	if v.Address == "" {
		return fmt.Errorf("%w: server", ErrRequired)
	}

	if err := v.Auth.Validate(); err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	// Validate that we can resolve Gateway host and user cert mounts/roles
	if v.GetGatewayHostCAMount() == "" {
		return fmt.Errorf("%w: mount is required (either at top level or in gatewayHostCA)", ErrRequired)
	}

	if v.GetGatewayUserCAMount() == "" {
		return fmt.Errorf("%w: mount is required (either at top level or in gatewayUserCA)", ErrRequired)
	}

	if v.GetGatewayHostCARole() == "" {
		return fmt.Errorf("%w: role is required (either at top level or in gatewayHostCA)", ErrRequired)
	}

	if v.GetGatewayUserCARole() == "" {
		return fmt.Errorf("%w: role is required (either at top level or in gatewayUserCA)", ErrRequired)
	}

	return nil
}

var (
	ErrConflictingAuthConfig     = errors.New("only one of 'token', 'appRole', 'gcp', or 'aws' can be specified for Vault auth")
	ErrConflictingSecretIDConfig = errors.New("only one of 'secretID' or 'secretIDFile' can be specified")
	ErrInvalidGCPType            = errors.New("gcp type must be 'gce' or 'iam'")
	ErrInvalidAWSType            = errors.New("aws type must be 'iam' or 'ec2'")
	ErrInvalidAWSSignatureType   = errors.New("aws signatureType must be 'identity', 'pkcs7', or 'rsa2048'")
)

func (a *SSHCAVaultAuthConfig) Validate() error {
	configuredMethods := a.countConfiguredMethods()
	if configuredMethods > 1 {
		return ErrConflictingAuthConfig
	}

	if a.AppRole != nil {
		if err := a.AppRole.Validate(); err != nil {
			return fmt.Errorf("appRole: %w", err)
		}
	}

	if a.GCP != nil {
		if err := a.GCP.Validate(); err != nil {
			return fmt.Errorf("gcp: %w", err)
		}
	}

	if a.AWS != nil {
		if err := a.AWS.Validate(); err != nil {
			return fmt.Errorf("aws: %w", err)
		}
	}

	return nil
}

func (a *SSHCAVaultAuthConfig) countConfiguredMethods() int {
	count := 0

	if a.Token != "" {
		count++
	}

	if a.AppRole != nil {
		count++
	}

	if a.GCP != nil {
		count++
	}

	if a.AWS != nil {
		count++
	}

	return count
}

const defaultAppRoleMount = "approle"

// GetMount returns the appRole mount path, defaulting to "approle" if not specified.
func (a *SSHCAVaultAppRoleConfig) GetMount() string {
	if a.Mount != "" {
		return a.Mount
	}

	return defaultAppRoleMount
}

func (a *SSHCAVaultAppRoleConfig) Validate() error {
	if a.RoleID == "" {
		return fmt.Errorf("%w: roleID", ErrRequired)
	}

	if a.SecretID != "" && a.SecretIDFile != "" {
		return ErrConflictingSecretIDConfig
	}

	if a.SecretID == "" && a.SecretIDFile == "" {
		return fmt.Errorf("%w: either secretID or secretIDFile is required", ErrRequired)
	}

	return nil
}

const defaultGCPMount = "gcp"

// GetMount returns the GCP auth mount path, defaulting to "gcp" if not specified.
func (g *SSHCAVaultGCPConfig) GetMount() string {
	if g.Mount != "" {
		return g.Mount
	}

	return defaultGCPMount
}

func (g *SSHCAVaultGCPConfig) Validate() error {
	if g.Role == "" {
		return fmt.Errorf("%w: role", ErrRequired)
	}

	if g.Type == "" {
		return fmt.Errorf("%w: type", ErrRequired)
	}

	gcpType := strings.ToLower(g.Type)

	switch gcpType {
	case "gce":
		return nil
	case "iam":
		if g.ServiceAccountEmail == "" {
			return fmt.Errorf("%w: serviceAccountEmail is required for iam type", ErrRequired)
		}

		return nil
	default:
		return ErrInvalidGCPType
	}
}

const defaultAWSMount = "aws"

// GetMount returns the AWS auth mount path, defaulting to "aws" if not specified.
func (a *SSHCAVaultAWSConfig) GetMount() string {
	if a.Mount != "" {
		return a.Mount
	}

	return defaultAWSMount
}

func (a *SSHCAVaultAWSConfig) Validate() error {
	if a.Role == "" {
		return fmt.Errorf("%w: role", ErrRequired)
	}

	if a.Type == "" {
		return fmt.Errorf("%w: type", ErrRequired)
	}

	awsType := strings.ToLower(a.Type)
	switch awsType {
	case "iam":
		return nil
	case "ec2":
		return a.validateEC2Type()
	default:
		return ErrInvalidAWSType
	}
}

func (a *SSHCAVaultAWSConfig) validateEC2Type() error {
	if a.SignatureType == "" {
		return nil
	}

	switch strings.ToLower(a.SignatureType) {
	case "identity", "pkcs7", "rsa2048":
		return nil
	default:
		return ErrInvalidAWSSignatureType
	}
}

const defaultVaultSSHMount = "ssh"

// GetGatewayHostCAMount returns the effective mount for Gateway host certificate signing.
func (v *SSHCAVaultConfig) GetGatewayHostCAMount() string {
	if v.GatewayHostCA != nil && v.GatewayHostCA.Mount != "" {
		return v.GatewayHostCA.Mount
	}

	if v.Mount != "" {
		return v.Mount
	}

	return defaultVaultSSHMount
}

// GetGatewayHostCARole returns the effective role for Gateway host certificate signing.
func (v *SSHCAVaultConfig) GetGatewayHostCARole() string {
	if v.GatewayHostCA != nil && v.GatewayHostCA.Role != "" {
		return v.GatewayHostCA.Role
	}

	return v.Role
}

// GetGatewayUserCAMount returns the effective mount for Gateway user certificate signing.
func (v *SSHCAVaultConfig) GetGatewayUserCAMount() string {
	if v.GatewayUserCA != nil && v.GatewayUserCA.Mount != "" {
		return v.GatewayUserCA.Mount
	}

	if v.Mount != "" {
		return v.Mount
	}

	return defaultVaultSSHMount
}

// GetGatewayUserCARole returns the effective role for Gateway user certificate signing.
func (v *SSHCAVaultConfig) GetGatewayUserCARole() string {
	if v.GatewayUserCA != nil && v.GatewayUserCA.Role != "" {
		return v.GatewayUserCA.Role
	}

	return v.Role
}

// GetUpstreamHostCAMount returns the effective mount for upstream host certificate verification.
func (v *SSHCAVaultConfig) GetUpstreamHostCAMount() string {
	if v.UpstreamHostCA != nil && v.UpstreamHostCA.Mount != "" {
		return v.UpstreamHostCA.Mount
	}

	if v.Mount != "" {
		return v.Mount
	}

	return defaultVaultSSHMount
}

// trustedDomainFor returns the trusted Twingate domain that host belongs to, or "" if none.
// A host matches a domain exactly or as a subdomain, so sharded hosts like us1.twingate.com are
// trusted.
func trustedDomainFor(host string) string {
	for domain := range issuerByDomain {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return domain
		}
	}

	return ""
}

func validatePort(port int, fieldName string) error {
	// Allow port 0 for dynamic port assignment in testing.
	if port < 0 || port > 65535 {
		return fmt.Errorf("%w: %s must be between 0 and 65535", ErrInvalidPort, fieldName)
	}

	return nil
}
