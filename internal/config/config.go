// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.yaml.in/yaml/v4"
	"golang.org/x/crypto/ssh"

	"gateway/internal/util/useragent"
	yamlutil "gateway/internal/util/yaml"
)

var (
	ErrRequired                         = errors.New("required field is missing")
	ErrInvalidNetwork                   = errors.New("invalid twingate.network")
	ErrInvalidHost                      = errors.New("invalid twingate.host")
	ErrInvalidPort                      = errors.New("invalid port number")
	ErrDuplicateUpstream                = errors.New("duplicate upstream name")
	ErrDuplicateUpstreamTrustedCABundle = errors.New("duplicate upstream trusted CA bundle file")
	ErrDuplicateTLSCert                 = errors.New("duplicate certificateFile")
	ErrInvalidSSHKeyType                = errors.New("invalid SSH key type")
	ErrNegativeTTL                      = errors.New("TTL must be non-negative")
)

// networkRegexp matches a twingate.network slug: 1-63 lowercase alphanumeric characters.
var networkRegexp = regexp.MustCompile(`^[a-z0-9]{1,63}$`)

// HostnameRegexp allows only valid DNS-label characters, permitting a single label (e.g. "test").
var HostnameRegexp = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

var issuerByDomain = map[string]string{
	"test":          "twingate-local",
	"dev.opstg.com": "twingate-dev",
	"stg.opstg.com": "twingate-stg",
	"sec.opstg.com": "twingate-sec",
	"twingate.com":  "twingate",
}

const (
	defaultTwingateHost                       = "twingate.com"
	defaultPort                               = 8443
	defaultMetricsPort                        = 9090
	defaultLogSystemLevel                     = zapcore.InfoLevel
	defaultSessionRecordingSegmentMaxDuration = time.Minute * 5
	defaultSessionRecordingSegmentMaxSize     = 64 * humanize.KiByte
	maxSessionRecordingSegmentMaxSize         = 256 * humanize.KiByte
	maxLogFileRotationMaxBackupAge            = 365 * 24 * time.Hour // 1 year
	maxLogFileRotationMaxSize                 = 1 * humanize.GiByte
	minTLSCertificateTTL                      = time.Minute * 10
)

type Config struct {
	Twingate                 TwingateConfig            `yaml:"twingate"`
	Port                     int                       `yaml:"port"                               jsonschema:"default=8443"`
	MetricsPort              int                       `yaml:"metricsPort"                        jsonschema:"default=9090"`
	Log                      LogConfig                 `yaml:"log"`
	TLS                      TLSConfig                 `yaml:"tls"`
	UpstreamTrustedCABundles []UpstreamTrustedCABundle `yaml:"upstreamTrustedCABundles,omitempty"`

	Kubernetes *KubernetesConfig `yaml:"kubernetes,omitempty"`
	SSH        *SSHConfig        `yaml:"ssh,omitempty"`
	WebApp     *WebAppConfig     `yaml:"webApp,omitempty"`
}

type TwingateConfig struct {
	// The Twingate network name, such as "acme" for acme.twingate.com.
	Network string `yaml:"network"`
	Host    string `yaml:"host"    jsonschema:"default=twingate.com"`
}

// JWKSURL returns the controller endpoint for fetching GAT signing keys.
func (t TwingateConfig) JWKSURL() string {
	return fmt.Sprintf("https://%s.%s/api/v1/jwk/ec", t.Network, t.Host)
}

// Issuer returns the expected JWT issuer for the configured controller host.
func (t TwingateConfig) Issuer() string {
	return issuerByDomain[trustedDomainFor(t.Host)]
}

type LogConfig struct {
	System           LogSystemConfig        `yaml:"system"`
	Audit            LogAuditConfig         `yaml:"audit"`
	SessionRecording SessionRecordingConfig `yaml:"sessionRecording"`
}

type LogSystemConfig struct {
	Level  zapcore.Level   `yaml:"level"  jsonschema:"default=info"`
	Output LogOutputConfig `yaml:"output"`
}

type LogAuditConfig struct {
	Output LogOutputConfig `yaml:"output"`
}

// SessionRecordingConfig configures recording of interactive sessions.
type SessionRecordingConfig struct {
	Segment SessionRecordingSegmentConfig `yaml:"segment"`
	Output  LogOutputConfig               `yaml:"output"`
}

// LogOutputConfig configures where output is written. At most one of stderr, stdout or file may be
// set; when none is set, output is written to stderr.
type LogOutputConfig struct {
	Stderr *LogStandardErrorConfig  `yaml:"stderr,omitempty"`
	Stdout *LogStandardOutputConfig `yaml:"stdout,omitempty"`
	File   *LogFileOutputConfig     `yaml:"file,omitempty"`
}

// LogStandardErrorConfig writes output to the process's standard error stream.
type LogStandardErrorConfig struct{}

// LogStandardOutputConfig writes output to the process's standard output stream.
type LogStandardOutputConfig struct{}

// LogFileOutputConfig writes output to a file. If the file already exists, output is appended to it.
type LogFileOutputConfig struct {
	// Path is the file to write to. If it already exists, it must be a regular file, not a
	// directory, device or symlink.
	Path     string                `yaml:"path"`
	Rotation LogFileRotationConfig `yaml:"rotation"`
}

// LogFileRotationConfig configures file rotation: when the file is rotated into a backup, and how
// backups are kept.
type LogFileRotationConfig struct {
	// MaxSize is the file size at which the active file is rotated, such as "100MiB". It is
	// rounded up to whole mebibytes (1MiB is 1,048,576 bytes), and 0 means the default. It can be
	// at most 1GiB.
	MaxSize yamlutil.ByteSize `yaml:"maxSize" jsonschema:"default=100MiB"`
	// MaxBackupFiles is how many backups are kept; the oldest is deleted beyond that. 0 means the
	// default.
	MaxBackupFiles int `yaml:"maxBackupFiles" jsonschema:"default=3"`
	// MaxBackupAge is how long a backup is kept before it is deleted, such as "7d" or "36h". It is
	// rounded up to whole days, so "36h" keeps backups for 2 days. When it is omitted or 0, backups
	// are kept until maxBackupFiles deletes them. It can be at most 365 days (1 year).
	MaxBackupAge yamlutil.Duration `yaml:"maxBackupAge"`
	// Compression is the algorithm that compresses each backup after rotation.
	Compression string `yaml:"compression" jsonschema:"default=none,enum=none,enum=gzip,enum=zstd"`
}

// SessionRecordingSegmentConfig configures when a recording is split into a new segment.
type SessionRecordingSegmentConfig struct {
	MaxDuration time.Duration     `yaml:"maxDuration" jsonschema:"default=5m"`
	MaxSize     yamlutil.ByteSize `yaml:"maxSize"     jsonschema:"default=64KiB"`
}

// TLSConfig configures the certificates the Gateway serves to clients. At least one of certificates
// or automation must be set.
type TLSConfig struct {
	Certificates *TLSCertificateSources `yaml:"certificates,omitempty"`
	Automation   *TLSAutomationConfig   `yaml:"automation,omitempty"`
}

// TLSCertificateSources configures the TLS certificates the Gateway can serve.
type TLSCertificateSources struct {
	Files []TLSCertificateFileKeyPair `yaml:"files"`
}

type TLSCertificateFileKeyPair struct {
	CertificateFile string `yaml:"certificateFile"`
	PrivateKeyFile  string `yaml:"privateKeyFile"`
}

// UpstreamTrustedCABundle is a PEM file of certificate authorities the Gateway trusts when verifying upstream TLS connections.
type UpstreamTrustedCABundle struct {
	File string `yaml:"file"`
}

// TLSAutomationConfig configures issuing the certificates served to clients on demand.
type TLSAutomationConfig struct {
	Certificate TLSAutomationCertificateConfig `yaml:"certificate"`
	Issuer      TLSIssuerConfig                `yaml:"issuer"`
}

type TLSAutomationCertificateConfig struct {
	CommonName string                  `yaml:"commonName"`
	TTL        time.Duration           `yaml:"ttl"        jsonschema:"default=24h"`
	Key        TLSCertificateKeyConfig `yaml:"key"`
}

type TLSCertificateKeyConfig struct {
	Type string `yaml:"type" jsonschema:"default=ecdsa,enum=ecdsa,enum=rsa"`
	// Bits is the key size: 256, 384 or 521 for ECDSA, and 2048, 3072 or 4096 for RSA. When it is
	// omitted, it is 256 for ECDSA and 2048 for RSA.
	Bits int `yaml:"bits"`
}

// TLSIssuerConfig configures the CA that signs automated certificates. Exactly one of local, vault
// or gcpPrivateCA must be set.
type TLSIssuerConfig struct {
	Local        *TLSLocalIssuerConfig        `yaml:"local,omitempty"`
	Vault        *TLSVaultIssuerConfig        `yaml:"vault,omitempty"`
	GCPPrivateCA *TLSGCPPrivateCAIssuerConfig `yaml:"gcpPrivateCA,omitempty"`
}

type TLSLocalIssuerConfig struct {
	CertificateFile string `yaml:"certificateFile"`
	PrivateKeyFile  string `yaml:"privateKeyFile"`
}

type TLSVaultIssuerConfig struct {
	VaultConfig `yaml:",inline"`

	Mount string `yaml:"mount,omitempty" jsonschema:"default=pki"`
	Role  string `yaml:"role"`
}

type TLSGCPPrivateCAIssuerConfig struct {
	Project  string `yaml:"project"`
	Location string `yaml:"location"`
	CAPoolID string `yaml:"caPoolID"`
	// Issues certificates from this CA in the pool instead of letting the pool choose one.
	IssuingCertificateAuthorityID string `yaml:"issuingCertificateAuthorityID,omitempty"`

	// The path to a Google Cloud credentials file. When it is omitted, Application Default
	// Credentials are used.
	CredentialsFile string `yaml:"credentialsFile,omitempty"`
}

// KubernetesConfig configures proxying to Kubernetes API servers.
type KubernetesConfig struct {
	Upstreams []KubernetesUpstream `yaml:"upstreams"`
}

// KubernetesUpstream is an external Kubernetes API server. At least one of bearerToken or
// bearerTokenFile must be set.
type KubernetesUpstream struct {
	Name            string `yaml:"name"`
	BearerToken     string `yaml:"bearerToken,omitempty"`
	BearerTokenFile string `yaml:"bearerTokenFile,omitempty"`
	CAFile          string `yaml:"caFile,omitempty"`
}

// SSHConfig configures proxying to SSH servers.
type SSHConfig struct {
	Gateway SSHGatewayConfig `yaml:"gateway"`
	CA      SSHCAConfig      `yaml:"ca"`
}

type SSHGatewayConfig struct {
	// Username is the user the Gateway connects to upstreams as.
	Username string       `yaml:"username"`
	Key      SSHKeyConfig `yaml:"key"`
	// HostCertificate is the certificate the Gateway presents to clients. Its ttl defaults to 24h.
	HostCertificate SSHCertificateConfig `yaml:"hostCertificate"`
	// UserCertificate is the certificate the Gateway presents to upstreams. Its ttl defaults to 5m.
	UserCertificate SSHCertificateConfig `yaml:"userCertificate"`
}

type SSHKeyConfig struct {
	// Type is the key type: ed25519, ecdsa, rsa, or an SSH key type identifier such as ssh-ed25519,
	// ssh-rsa, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384 or ecdsa-sha2-nistp521.
	Type string `yaml:"type" jsonschema:"default=ed25519"`
	// Bits is the key size: 256, 384 or 521 for ECDSA, and 2048, 3072 or 4096 for RSA. When it is
	// omitted, it is 256 for ECDSA and 4096 for RSA.
	Bits int `yaml:"bits"`
}

type SSHCertificateConfig struct {
	TTL time.Duration `yaml:"ttl"`
}

// SSHCAConfig configures the CA that signs the Gateway's SSH certificates. Exactly one of local or
// vault must be set.
type SSHCAConfig struct {
	Local *SSHCALocalConfig `yaml:"local,omitempty"`
	Vault *SSHCAVaultConfig `yaml:"vault,omitempty"`
}

// SSHCALocalConfig configures a CA that signs locally on the Gateway.
type SSHCALocalConfig struct {
	// PrivateKeyFile is the path to the unencrypted CA private key, OpenSSH or PEM encoded.
	PrivateKeyFile string `yaml:"privateKeyFile"`
}

// SSHCAVaultConfig configures CAs backed by Vault's SSH secrets engine.
type SSHCAVaultConfig struct {
	VaultConfig `yaml:",inline"`

	// The default SSH secrets engine mount and role, used by every CA that does not override them
	// below.
	Mount string `yaml:"mount,omitempty" jsonschema:"default=ssh"`
	Role  string `yaml:"role,omitempty"`

	// GatewayHostCA is the CA that signs the host certificates the Gateway presents to clients.
	GatewayHostCA *SSHCAVaultCertConfig `yaml:"gatewayHostCA,omitempty"`
	// GatewayUserCA is the CA that signs the user certificates the Gateway presents to upstreams.
	GatewayUserCA *SSHCAVaultCertConfig `yaml:"gatewayUserCA,omitempty"`
	// UpstreamHostCA is the CA whose public key verifies the host certificates of upstreams.
	UpstreamHostCA *SSHCAVaultMountConfig `yaml:"upstreamHostCA,omitempty"`
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

// VaultConfig holds the connection settings shared by every Vault-backed CA.
type VaultConfig struct {
	// Address is the Vault server address, such as https://vault.example.com:8200.
	Address string `yaml:"address"`
	// CABundleFile is the path to a PEM CA bundle that verifies Vault's TLS certificate. When it is
	// omitted, the system trust store is used.
	CABundleFile string          `yaml:"caBundleFile,omitempty"`
	Auth         VaultAuthConfig `yaml:"auth"`

	// Namespace is the Vault namespace.
	Namespace string `yaml:"namespace,omitempty"`
}

// VaultAuthConfig configures how the Gateway authenticates to Vault.
// At most one method may be set. If none is set, the token is read from the
// VAULT_TOKEN environment variable.
type VaultAuthConfig struct {
	// Token is a static Vault token, for development and testing only. In production, deliver the
	// token through the VAULT_TOKEN environment variable from a secret store.
	Token   string              `yaml:"token,omitempty"`
	AppRole *VaultAppRoleConfig `yaml:"appRole,omitempty"`
	GCP     *VaultGCPConfig     `yaml:"gcp,omitempty"`
	AWS     *VaultAWSConfig     `yaml:"aws,omitempty"`
}

// VaultAppRoleConfig configures Vault AppRole authentication.
// Exactly one of secretID or secretIDFile must be set.
type VaultAppRoleConfig struct {
	// Mount is the AppRole auth mount path.
	Mount  string `yaml:"mount,omitempty" jsonschema:"default=approle"`
	RoleID string `yaml:"roleID"`
	// SecretID is the SecretID inline, for development and testing only.
	SecretID string `yaml:"secretID"`
	// SecretIDFile is the path to a file containing the SecretID. Use it in production.
	SecretIDFile string `yaml:"secretIDFile"`
}

// VaultGCPConfig configures Vault GCP authentication.
type VaultGCPConfig struct {
	// Mount is the GCP auth mount path.
	Mount string `yaml:"mount,omitempty" jsonschema:"default=gcp"`
	// Role is the Vault GCP auth role to log in as.
	Role string `yaml:"role"`
	Type string `yaml:"type" jsonschema:"enum=gce,enum=iam"`

	// ServiceAccountEmail is the service account to authenticate as. It is required when type is
	// "iam".
	ServiceAccountEmail string `yaml:"serviceAccountEmail,omitempty"`
}

// VaultAWSConfig configures Vault AWS authentication.
type VaultAWSConfig struct {
	// Mount is the AWS auth mount path.
	Mount string `yaml:"mount,omitempty" jsonschema:"default=aws"`
	// Role is the Vault AWS auth role to log in as.
	Role   string `yaml:"role"`
	Type   string `yaml:"type"             jsonschema:"enum=iam,enum=ec2"`
	Region string `yaml:"region,omitempty"`
	// IAMServerIDHeader is the value of the X-Vault-AWS-IAM-Server-ID header.
	IAMServerIDHeader string `yaml:"iamServerIDHeader,omitempty"`

	// SignatureType is the signature type of the EC2 instance identity document. It is used when
	// type is "ec2".
	SignatureType string `yaml:"signatureType,omitempty" jsonschema:"default=rsa2048,enum=rsa2048,enum=identity,enum=pkcs7"`
	// Nonce is the client nonce for EC2 authentication. It is used when type is "ec2".
	Nonce string `yaml:"nonce,omitempty"`
}

// WebAppConfig configures proxying to HTTP web apps.
type WebAppConfig struct {
	// RequestHeaders maps header names to the values set on requests to the upstream. A value may
	// contain one {{key}}, such as "Bearer {{jwt}}", where key is jwt, username, groups,
	// clientGeoLatLong, clientGeoCity, clientGeoRegion or clientGeoCountry.
	RequestHeaders map[string]string `yaml:"requestHeaders,omitempty"`
}

func newDefaultConfig() *Config {
	return &Config{
		Port:        defaultPort,
		MetricsPort: defaultMetricsPort,
		Twingate: TwingateConfig{
			Host: defaultTwingateHost,
		},
		Log: LogConfig{
			System: LogSystemConfig{
				Level: defaultLogSystemLevel,
			},
			SessionRecording: SessionRecordingConfig{
				Segment: SessionRecordingSegmentConfig{
					MaxDuration: defaultSessionRecordingSegmentMaxDuration,
					MaxSize:     defaultSessionRecordingSegmentMaxSize,
				},
			},
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

// stripNetworkPrefix lowercases hostname and removes a leading "<network>." label if present.
func stripNetworkPrefix(hostname, network string) string {
	return strings.TrimPrefix(strings.ToLower(hostname), strings.ToLower(network)+".")
}

func resolveTwingateHostname(targetURL, defaultHost string, retryMax int, logger *zap.Logger) string {
	logger = logger.With(zap.String("url", targetURL), zap.String("default_host", defaultHost))

	client := retryablehttp.NewClient()
	client.HTTPClient.Transport = useragent.Transport{Base: client.HTTPClient.Transport}
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
		logger.Warn("No redirect received", zap.Int("status_code", resp.StatusCode))

		return defaultHost
	}

	location, err := resp.Location()
	if err != nil {
		logger.Warn("Failed to parse redirect location", zap.Error(err))

		return defaultHost
	}

	resolved := location.Hostname()
	if err := validateHost(resolved); err != nil {
		logger.Warn("Resolved Twingate host failed validation, keeping configured host",
			zap.String("resolved_host", resolved), zap.Error(err))

		return defaultHost
	}

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

	if !networkRegexp.MatchString(c.Twingate.Network) {
		return fmt.Errorf("%w: must be 1-63 lowercase alphanumeric characters: %q", ErrInvalidNetwork, c.Twingate.Network)
	}

	if err := validateHost(c.Twingate.Host); err != nil {
		return err
	}

	if err := validatePort(c.Port, "port"); err != nil {
		return err
	}

	if err := validatePort(c.MetricsPort, "metricsPort"); err != nil {
		return err
	}

	if err := c.Log.Validate(); err != nil {
		return fmt.Errorf("log config: %w", err)
	}

	if err := c.TLS.Validate(); err != nil {
		return fmt.Errorf("tls config: %w", err)
	}

	if err := validateUpstreamTrustedCABundles(c.UpstreamTrustedCABundles); err != nil {
		return fmt.Errorf("upstreamTrustedCABundles config: %w", err)
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

var (
	errNegativeDuration     = errors.New("duration must be non-negative")
	errSizeOutOfRange       = errors.New("size must be greater than 0 and at most 256KiB")
	errMultipleOutputs      = errors.New("only one of stderr, stdout or file may be set")
	errUnsupportedLogLevel  = errors.New("must be debug, info, warn or error")
	errDuplicateLogFilePath = errors.New("duplicate log file path")
)

func (l *LogConfig) Validate() error {
	if err := l.System.Validate(); err != nil {
		return fmt.Errorf("system: %w", err)
	}

	if err := l.Audit.Validate(); err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	if err := l.SessionRecording.Validate(); err != nil {
		return fmt.Errorf("sessionRecording: %w", err)
	}

	return l.validateUniqueFilePaths()
}

func (l *LogConfig) validateUniqueFilePaths() error {
	paths := map[string]bool{}

	for _, output := range []LogOutputConfig{l.System.Output, l.Audit.Output, l.SessionRecording.Output} {
		if output.File == nil {
			continue
		}

		// Abs also resolves a relative path against the working directory, so two spellings of one file
		// count as one.
		path, err := filepath.Abs(output.File.Path)
		if err != nil {
			return fmt.Errorf("file path %s: %w", output.File.Path, err)
		}

		if paths[path] {
			return fmt.Errorf("%w: %s", errDuplicateLogFilePath, path)
		}

		paths[path] = true
	}

	return nil
}

func (s *LogSystemConfig) Validate() error {
	if s.Level < zapcore.DebugLevel || s.Level > zapcore.ErrorLevel {
		return fmt.Errorf("%w: level", errUnsupportedLogLevel)
	}

	if err := s.Output.Validate(); err != nil {
		return fmt.Errorf("output: %w", err)
	}

	return nil
}

func (a *LogAuditConfig) Validate() error {
	if err := a.Output.Validate(); err != nil {
		return fmt.Errorf("output: %w", err)
	}

	return nil
}

func (s *SessionRecordingConfig) Validate() error {
	if err := s.Segment.Validate(); err != nil {
		return fmt.Errorf("segment: %w", err)
	}

	if err := s.Output.Validate(); err != nil {
		return fmt.Errorf("output: %w", err)
	}

	return nil
}

func (s *SessionRecordingSegmentConfig) Validate() error {
	if s.MaxDuration < 0 {
		return fmt.Errorf("%w: maxDuration", errNegativeDuration)
	}

	if s.MaxSize <= 0 || s.MaxSize > maxSessionRecordingSegmentMaxSize {
		return fmt.Errorf("%w: maxSize", errSizeOutOfRange)
	}

	return nil
}

func (o *LogOutputConfig) Validate() error {
	if countTrue(o.Stderr != nil, o.Stdout != nil, o.File != nil) > 1 {
		return errMultipleOutputs
	}

	if o.File != nil {
		if err := o.File.Validate(); err != nil {
			return fmt.Errorf("file: %w", err)
		}
	}

	return nil
}

var (
	errLogFileSizeOutOfRange  = errors.New("size must be non-negative and at most 1GiB")
	errNegativeCount          = errors.New("count must be non-negative")
	errDurationTooLong        = errors.New("duration must be at most 365 days")
	errUnsupportedCompression = errors.New("must be none, gzip or zstd")
	errNotRegularFile         = errors.New("must be a regular file")
)

func (f *LogFileOutputConfig) Validate() error {
	if f.Path == "" {
		return fmt.Errorf("%w: path", ErrRequired)
	}

	// timberjack renames whatever exists at the path when it cannot append to it, so a
	// directory would be silently renamed, and a device such as /dev/null fails to rotate.
	// Lstat also rejects a symlink: rotation renames the link rather than its target, so logs
	// written after the first rotation never reach the target.
	if info, err := os.Lstat(f.Path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%w: path", errNotRegularFile)
	}

	if err := f.Rotation.Validate(); err != nil {
		return fmt.Errorf("rotation: %w", err)
	}

	return nil
}

func (r *LogFileRotationConfig) Validate() error {
	if r.MaxSize < 0 || r.MaxSize > maxLogFileRotationMaxSize {
		return fmt.Errorf("%w: maxSize", errLogFileSizeOutOfRange)
	}

	if r.MaxBackupFiles < 0 {
		return fmt.Errorf("%w: maxBackupFiles", errNegativeCount)
	}

	if time.Duration(r.MaxBackupAge) > maxLogFileRotationMaxBackupAge {
		return fmt.Errorf("%w: maxBackupAge", errDurationTooLong)
	}

	switch r.Compression {
	case "", "none", "gzip", "zstd":
		return nil
	default:
		return fmt.Errorf("%w: compression", errUnsupportedCompression)
	}
}

const (
	defaultLogFileRotationMaxSize        = 100 * humanize.MiByte
	defaultLogFileRotationMaxBackupFiles = 3
	defaultLogFileRotationCompression    = "none"
)

// GetMaxSize returns MaxSize in whole mebibytes, rounded up, defaulting to 100MiB.
func (r *LogFileRotationConfig) GetMaxSize() int {
	maxSize := r.MaxSize
	if maxSize == 0 {
		maxSize = defaultLogFileRotationMaxSize
	}

	return int(math.Ceil(float64(maxSize.Bytes()) / humanize.MiByte))
}

// GetMaxBackupFiles returns MaxBackupFiles, defaulting to 3.
func (r *LogFileRotationConfig) GetMaxBackupFiles() int {
	if r.MaxBackupFiles == 0 {
		return defaultLogFileRotationMaxBackupFiles
	}

	return r.MaxBackupFiles
}

// GetMaxBackupAge returns MaxBackupAge in whole days, rounded up, defaulting to 0 (no limit).
func (r *LogFileRotationConfig) GetMaxBackupAge() int {
	return int((time.Duration(r.MaxBackupAge) + humanize.Day - 1) / humanize.Day)
}

// GetCompression returns Compression, defaulting to "none".
func (r *LogFileRotationConfig) GetCompression() string {
	if r.Compression == "" {
		return defaultLogFileRotationCompression
	}

	return r.Compression
}

var (
	ErrMissingTLSCertificateSource = errors.New("either 'certificates' or 'automation' must be specified for TLS config")
	ErrMissingTLSIssuerConfig      = errors.New("at least one TLS issuer must be configured")
	ErrConflictingTLSIssuerConfig  = errors.New("only one of 'local', 'vault' or 'gcpPrivateCA' can be specified for TLS issuer config")
	ErrInvalidTLSKeyType           = errors.New("invalid TLS key type")
	errShortTTL                    = errors.New("TTL is too short")
)

func (t *TLSConfig) Validate() error {
	if t.Certificates == nil && t.Automation == nil {
		return ErrMissingTLSCertificateSource
	}

	if t.Certificates != nil {
		if err := t.Certificates.Validate(); err != nil {
			return fmt.Errorf("certificates: %w", err)
		}
	}

	if t.Automation != nil {
		if err := t.Automation.Validate(); err != nil {
			return fmt.Errorf("automation: %w", err)
		}
	}

	return nil
}

func (t *TLSCertificateSources) Validate() error {
	if len(t.Files) == 0 {
		return fmt.Errorf("%w: files", ErrRequired)
	}

	certificateFiles := make(map[string]struct{})

	for i, keyPair := range t.Files {
		if err := keyPair.Validate(); err != nil {
			return fmt.Errorf("files[%d]: %w", i, err)
		}

		if _, exists := certificateFiles[keyPair.CertificateFile]; exists {
			return fmt.Errorf("%w: %q", ErrDuplicateTLSCert, keyPair.CertificateFile)
		}

		certificateFiles[keyPair.CertificateFile] = struct{}{}
	}

	return nil
}

func (t *TLSCertificateFileKeyPair) Validate() error {
	if t.CertificateFile == "" {
		return fmt.Errorf("%w: certificateFile", ErrRequired)
	}

	if t.PrivateKeyFile == "" {
		return fmt.Errorf("%w: privateKeyFile", ErrRequired)
	}

	return nil
}

func (a *TLSAutomationConfig) Validate() error {
	if err := a.Certificate.Validate(); err != nil {
		return fmt.Errorf("certificate: %w", err)
	}

	if err := a.Issuer.Validate(); err != nil {
		return fmt.Errorf("issuer: %w", err)
	}

	if a.Issuer.GCPPrivateCA != nil && a.Certificate.CommonName == "" {
		return fmt.Errorf("certificate: %w: commonName is required for gcpPrivateCA issuer", ErrRequired)
	}

	return nil
}

func (c *TLSAutomationCertificateConfig) Validate() error {
	if c.TTL < 0 {
		return fmt.Errorf("%w: ttl", ErrNegativeTTL)
	}

	if c.TTL != 0 && c.TTL < minTLSCertificateTTL {
		return fmt.Errorf("%w: TTL must be at least %s", errShortTTL, minTLSCertificateTTL)
	}

	if err := c.Key.Validate(); err != nil {
		return fmt.Errorf("key: %w", err)
	}

	return nil
}

func (k *TLSCertificateKeyConfig) Validate() error {
	switch k.Type {
	case "", "ecdsa", "rsa":
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidTLSKeyType, k.Type)
	}
}

func (i *TLSIssuerConfig) Validate() error {
	switch configured := countTrue(i.Local != nil, i.Vault != nil, i.GCPPrivateCA != nil); {
	case configured == 0:
		return ErrMissingTLSIssuerConfig
	case configured > 1:
		return ErrConflictingTLSIssuerConfig
	}

	if i.Local != nil {
		if err := i.Local.Validate(); err != nil {
			return fmt.Errorf("local: %w", err)
		}
	}

	if i.Vault != nil {
		if err := i.Vault.Validate(); err != nil {
			return fmt.Errorf("vault: %w", err)
		}
	}

	if i.GCPPrivateCA != nil {
		if err := i.GCPPrivateCA.Validate(); err != nil {
			return fmt.Errorf("gcpPrivateCA: %w", err)
		}
	}

	return nil
}

func (l *TLSLocalIssuerConfig) Validate() error {
	if l.CertificateFile == "" {
		return fmt.Errorf("%w: certificateFile", ErrRequired)
	}

	if l.PrivateKeyFile == "" {
		return fmt.Errorf("%w: privateKeyFile", ErrRequired)
	}

	return nil
}

func (v *VaultConfig) Validate() error {
	if v.Address == "" {
		return fmt.Errorf("%w: address", ErrRequired)
	}

	if err := v.Auth.Validate(); err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	return nil
}

func (v *TLSVaultIssuerConfig) Validate() error {
	if err := v.VaultConfig.Validate(); err != nil {
		return err
	}

	if v.Role == "" {
		return fmt.Errorf("%w: role", ErrRequired)
	}

	return nil
}

func (g *TLSGCPPrivateCAIssuerConfig) Validate() error {
	if g.Project == "" {
		return fmt.Errorf("%w: project", ErrRequired)
	}

	if g.Location == "" {
		return fmt.Errorf("%w: location", ErrRequired)
	}

	if g.CAPoolID == "" {
		return fmt.Errorf("%w: caPoolID", ErrRequired)
	}

	return nil
}

const defaultVaultPKIMount = "pki"

// GetMount returns the PKI secrets engine mount point, defaulting to "pki".
func (v *TLSVaultIssuerConfig) GetMount() string {
	if v.Mount != "" {
		return v.Mount
	}

	return defaultVaultPKIMount
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

func validateUpstreamTrustedCABundles(caBundles []UpstreamTrustedCABundle) error {
	bundleFiles := make(map[string]struct{})

	for i, caBundle := range caBundles {
		if err := caBundle.Validate(); err != nil {
			return fmt.Errorf("upstreamTrustedCABundles[%d]: %w", i, err)
		}

		if _, exists := bundleFiles[caBundle.File]; exists {
			return fmt.Errorf("%w: %q", ErrDuplicateUpstreamTrustedCABundle, caBundle.File)
		}

		bundleFiles[caBundle.File] = struct{}{}
	}

	return nil
}

func (c *UpstreamTrustedCABundle) Validate() error {
	if c.File == "" {
		return fmt.Errorf("%w: file", ErrRequired)
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
	switch k.Type {
	case "", "ed25519", "ecdsa", "rsa",
		ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA:
		return nil
	default:
		return ErrInvalidSSHKeyType
	}
}

func (c *SSHCertificateConfig) Validate() error {
	if c.TTL < 0 {
		return ErrNegativeTTL
	}

	return nil
}

var (
	ErrMissingCAConfig     = errors.New("either 'local' or 'vault' must be specified for CA config")
	ErrConflictingCAConfig = errors.New("only one of 'local' or 'vault' can be specified for CA config")
)

func (c *SSHCAConfig) Validate() error {
	if c.Local == nil && c.Vault == nil {
		return ErrMissingCAConfig
	}

	if c.Local != nil && c.Vault != nil {
		return ErrConflictingCAConfig
	}

	if c.Local != nil {
		if err := c.Local.Validate(); err != nil {
			return fmt.Errorf("local: %w", err)
		}
	}

	if c.Vault != nil {
		if err := c.Vault.Validate(); err != nil {
			return fmt.Errorf("vault: %w", err)
		}
	}

	return nil
}

func (m *SSHCALocalConfig) Validate() error {
	if m.PrivateKeyFile == "" {
		return fmt.Errorf("%w: privateKeyFile", ErrRequired)
	}

	return nil
}

func (v *SSHCAVaultConfig) Validate() error {
	if err := v.VaultConfig.Validate(); err != nil {
		return err
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

func (a *VaultAuthConfig) Validate() error {
	if countTrue(a.Token != "", a.AppRole != nil, a.GCP != nil, a.AWS != nil) > 1 {
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

const defaultAppRoleMount = "approle"

// GetMount returns the appRole mount path, defaulting to "approle" if not specified.
func (a *VaultAppRoleConfig) GetMount() string {
	if a.Mount != "" {
		return a.Mount
	}

	return defaultAppRoleMount
}

func (a *VaultAppRoleConfig) Validate() error {
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
func (g *VaultGCPConfig) GetMount() string {
	if g.Mount != "" {
		return g.Mount
	}

	return defaultGCPMount
}

func (g *VaultGCPConfig) Validate() error {
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

const (
	defaultAWSMount         = "aws"
	defaultAWSSignatureType = "rsa2048"
)

// GetMount returns the AWS auth mount path, defaulting to "aws" if not specified.
func (a *VaultAWSConfig) GetMount() string {
	if a.Mount != "" {
		return a.Mount
	}

	return defaultAWSMount
}

// GetSignatureType returns the EC2 auth signature type, defaulting to "rsa2048"
// (SHA-256) when unset rather than the Vault SDK's pkcs7 (SHA-1) default.
func (a *VaultAWSConfig) GetSignatureType() string {
	if a.SignatureType != "" {
		return a.SignatureType
	}

	return defaultAWSSignatureType
}

func (a *VaultAWSConfig) Validate() error {
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

func (a *VaultAWSConfig) validateEC2Type() error {
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

// validateHost checks host is a well-formed hostname for a trusted Twingate controller domain.
func validateHost(host string) error {
	if !HostnameRegexp.MatchString(host) {
		return fmt.Errorf("%w: not a valid hostname: %q", ErrInvalidHost, host)
	}

	if trustedDomainFor(host) == "" {
		return fmt.Errorf("%w: not a trusted Twingate domain: %q", ErrInvalidHost, host)
	}

	return nil
}

// trustedDomainFor returns the trusted Twingate domain that host belongs to, or "" if none.
// A host matches a domain exactly or as a subdomain, so sharded hosts like us1.twingate.com are
// trusted. Matching is case-insensitive.
func trustedDomainFor(host string) string {
	lowered := strings.ToLower(host)
	for domain := range issuerByDomain {
		if lowered == domain || strings.HasSuffix(lowered, "."+domain) {
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

func countTrue(values ...bool) int {
	count := 0

	for _, v := range values {
		if v {
			count++
		}
	}

	return count
}
