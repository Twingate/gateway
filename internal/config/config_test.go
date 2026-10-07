// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	yamlutil "gateway/internal/util/yaml"
)

func TestStripNetworkPrefix(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		network  string
		expected string
	}{
		{name: "sharded host", hostname: "acme.us1.test.com", network: "acme", expected: "us1.test.com"},
		{name: "non-sharded host", hostname: "acme.test.com", network: "acme", expected: "test.com"},
		{name: "no network prefix", hostname: "test.com", network: "acme", expected: "test.com"},
		{name: "empty network", hostname: "us1.twingate.com", network: "", expected: "us1.twingate.com"},
		{name: "uppercase host prefix", hostname: "ACME.us1.twingate.com", network: "acme", expected: "us1.twingate.com"},
		{name: "uppercase network", hostname: "acme.us1.twingate.com", network: "ACME", expected: "us1.twingate.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, stripNetworkPrefix(tt.hostname, tt.network))
		})
	}
}

func TestTwingateConfig_JWKSURL(t *testing.T) {
	cfg := TwingateConfig{Network: "acme", Host: "twingate.com"}
	assert.Equal(t, "https://acme.twingate.com/api/v1/jwk/ec", cfg.JWKSURL())
}

func TestTwingateConfig_Issuer(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		issuer string
	}{
		{name: "exact match", host: "twingate.com", issuer: "twingate"},
		{name: "sharded host", host: "us1.twingate.com", issuer: "twingate"},
		{name: "unknown host", host: "unknown-dev.opstg.com", issuer: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.issuer, TwingateConfig{Host: tt.host}.Issuer())
		})
	}
}

func TestResolveTwingateHostname(t *testing.T) {
	t.Run("returns location hostname on 308 status code", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://acme.us1.twingate.com/api/v1/jwk/ec")
			w.WriteHeader(http.StatusPermanentRedirect)
		}))
		t.Cleanup(server.Close)

		result := resolveTwingateHostname(server.URL+"/api/v1/jwk/ec", "twingate.com", 0, zap.NewNop())
		assert.Equal(t, "acme.us1.twingate.com", result)
	})

	t.Run("returns default host when resolved host is untrusted", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://evil.com/api/v1/jwk/ec")
			w.WriteHeader(http.StatusPermanentRedirect)
		}))
		t.Cleanup(server.Close)

		result := resolveTwingateHostname(server.URL+"/api/v1/jwk/ec", "twingate.com", 0, zap.NewNop())
		assert.Equal(t, "twingate.com", result)
	})

	t.Run("returns default host on empty location", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "")
			w.WriteHeader(http.StatusPermanentRedirect)
		}))
		t.Cleanup(server.Close)

		result := resolveTwingateHostname(server.URL+"/api/v1/jwk/ec", "twingate.com", 0, zap.NewNop())

		assert.Equal(t, "twingate.com", result)
	})

	t.Run("returns default host on non 308 status code", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)

		result := resolveTwingateHostname(server.URL+"/api/v1/jwk/ec", "twingate.com", 0, zap.NewNop())

		assert.Equal(t, "twingate.com", result)
	})

	t.Run("identifies the gateway with a User-Agent header", func(t *testing.T) {
		userAgents := make(chan string, 1)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userAgents <- r.UserAgent()

			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)

		resolveTwingateHostname(server.URL+"/api/v1/jwk/ec", "twingate.com", 0, zap.NewNop())

		select {
		case userAgent := <-userAgents:
			assert.Equal(t, "Twingate-Gateway/dev", userAgent)
		default:
			t.Fatal("hostname resolution endpoint was not requested")
		}
	})

	t.Run("does not follow redirect", func(t *testing.T) {
		shardServerCalled := make(chan struct{}, 1)

		shardServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			shardServerCalled <- struct{}{}

			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(shardServer.Close)

		redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, shardServer.URL+r.URL.Path, http.StatusPermanentRedirect) //nolint:gosec // G710: redirects to the test server, not a caller-supplied host
		}))
		t.Cleanup(redirectServer.Close)

		resolveTwingateHostname(redirectServer.URL+"/api/v1/jwk/ec", "twingate.com", 0, zap.NewNop())

		select {
		case <-shardServerCalled:
			t.Fatal("should not follow redirect to shard server")
		default:
		}
	})

	t.Run("returns default host on connection error", func(t *testing.T) {
		result := resolveTwingateHostname("http://127.0.0.1:1/api/v1/jwk/ec", "twingate.com", 0, zap.NewNop())

		assert.Equal(t, "twingate.com", result)
	})
}

func TestLoad_Log(t *testing.T) {
	yaml := `
twingate:
  network: "acme"
log:
  system:
    level: debug
    output:
      stdout: {}
  audit:
    output:
      file:
        path: /var/log/gateway/audit.log
        rotation:
          maxSize: 10MB
          maxBackupFiles: 5
          maxAge: 36h
          compression: gzip
  sessionRecording:
    output:
      stderr: {}
tls:
  certificates:
    files:
      - certificateFile: "tls.crt"
        privateKeyFile: "tls.key"
kubernetes: {}
`

	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(tmpFile, []byte(yaml), 0600))

	cfg, err := Load(tmpFile)
	require.NoError(t, err)

	assert.Equal(t, zapcore.DebugLevel, cfg.Log.System.Level)
	assert.Equal(t, LogOutputConfig{Stdout: &LogStandardOutputConfig{}}, cfg.Log.System.Output)
	assert.Equal(t, LogOutputConfig{File: &LogFileOutputConfig{
		Path: "/var/log/gateway/audit.log",
		Rotation: LogFileRotationConfig{
			MaxSize:        10_000_000,
			MaxBackupFiles: 5,
			MaxAge:         new(yamlutil.Duration(36 * time.Hour)),
			Compression:    "gzip",
		},
	}}, cfg.Log.Audit.Output)
	assert.Equal(t, LogOutputConfig{Stderr: &LogStandardErrorConfig{}}, cfg.Log.SessionRecording.Output)
}

func TestLoad_LogFileRotation(t *testing.T) {
	tests := []struct {
		name     string
		rotation string
		want     LogFileRotationConfig
	}{
		{name: "rotation omitted"},
		{
			name: "explicit zero maxAge is kept",
			rotation: `
        rotation:
          maxAge: 0h`,
			want: LogFileRotationConfig{MaxAge: new(yamlutil.Duration(0))},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `
twingate:
  network: "acme"
log:
  audit:
    output:
      file:
        path: /var/log/gateway/audit.log` + tt.rotation + `
tls:
  certificates:
    files:
      - certificateFile: "tls.crt"
        privateKeyFile: "tls.key"
kubernetes: {}
`

			tmpFile := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(tmpFile, []byte(yaml), 0600))

			cfg, err := Load(tmpFile)
			require.NoError(t, err)

			assert.Equal(t, tt.want, cfg.Log.Audit.Output.File.Rotation)
		})
	}
}

func TestLoad_TLSAutomation(t *testing.T) {
	yaml := `
twingate:
  network: "acme"
port: 8443
metricsPort: 9090
tls:
  certificates:
    files:
      - certificateFile: "tls.crt"
        privateKeyFile: "tls.key"
  automation:
    certificate:
      commonName: "gateway.acme.int"
      ttl: "48h"
      key:
        type: "ecdsa"
        bits: 384
    issuer:
      local:
        certificateFile: "ca.crt"
        privateKeyFile: "ca.key"
webApp: {}
`

	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(tmpFile, []byte(yaml), 0600)
	require.NoError(t, err)

	cfg, err := Load(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, cfg.TLS.Automation)
	require.NotNil(t, cfg.TLS.Certificates)

	assert.Equal(t, []TLSCertificateFileKeyPair{{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"}}, cfg.TLS.Certificates.Files)

	require.NotNil(t, cfg.TLS.Automation.Issuer.Local)
	assert.Equal(t, "ca.crt", cfg.TLS.Automation.Issuer.Local.CertificateFile)
	assert.Equal(t, "ca.key", cfg.TLS.Automation.Issuer.Local.PrivateKeyFile)
	assert.Equal(t, "gateway.acme.int", cfg.TLS.Automation.Certificate.CommonName)
	assert.Equal(t, 48*time.Hour, cfg.TLS.Automation.Certificate.TTL)
	assert.Equal(t, "ecdsa", cfg.TLS.Automation.Certificate.Key.Type)
	assert.Equal(t, 384, cfg.TLS.Automation.Certificate.Key.Bits)

	assert.NoError(t, cfg.Validate())
}

func TestLoad_Kubernetes(t *testing.T) {
	yaml := `
twingate:
  network: "acme"
port: 8443
metricsPort: 9090
log:
  sessionRecording:
    segment:
      maxDuration: "30s"
      maxSize: "128KB"
tls:
  certificates:
    files:
      - certificateFile: "tls.crt"
        privateKeyFile: "tls.key"
kubernetes: {}
`

	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(tmpFile, []byte(yaml), 0600)
	require.NoError(t, err)

	cfg, err := Load(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify basic config
	assert.Equal(t, "acme", cfg.Twingate.Network)
	assert.Equal(t, 8443, cfg.Port)
	assert.Equal(t, 9090, cfg.MetricsPort)
	assert.Equal(t, time.Second*30, cfg.Log.SessionRecording.Segment.MaxDuration)
	assert.Equal(t, 128_000, cfg.Log.SessionRecording.Segment.MaxSize.Bytes())

	require.NotNil(t, cfg.Kubernetes)
	assert.Empty(t, cfg.Kubernetes.Upstreams)
	assert.Nil(t, cfg.SSH)
}

func TestLoad_SSH(t *testing.T) {
	yaml := `
twingate:
  network: "acme"
port: 8443
metricsPort: 9090
tls:
  certificates:
    files:
      - certificateFile: "tls.crt"
        privateKeyFile: "tls.key"
ssh:
  gateway:
    username: "gateway"
    key:
      type: "ed25519"
    hostCertificate:
      ttl: "24h"
    userCertificate:
      ttl: "5m"
  ca:
    local:
      privateKeyFile: "ca.key"
`

	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(tmpFile, []byte(yaml), 0600)
	require.NoError(t, err)

	cfg, err := Load(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Nil(t, cfg.Kubernetes)
	require.NotNil(t, cfg.SSH)

	// Verify SSH config
	assert.Equal(t, "ed25519", cfg.SSH.Gateway.Key.Type)
	assert.Equal(t, 24*time.Hour, cfg.SSH.Gateway.HostCertificate.TTL)
	assert.Equal(t, 5*time.Minute, cfg.SSH.Gateway.UserCertificate.TTL)
	require.NotNil(t, cfg.SSH.CA.Local)
}

func TestLoad_SSH_Vault(t *testing.T) {
	yaml := `
twingate:
  network: "acme"
tls:
  certificates:
    files:
      - certificateFile: "tls.crt"
        privateKeyFile: "tls.key"
ssh:
  gateway:
    username: "gateway"
    key:
      type: "ed25519"
    hostCertificate:
      ttl: "24h"
    userCertificate:
      ttl: "5m"
  ca:
    vault:
      address: "https://vault:8200"
      mount: "ssh-default"
      role: "gateway"
      gatewayHostCA:
        mount: "ssh-gateway-host"
        role: "gateway"
      gatewayUserCA:
        mount: "ssh-gateway-user"
        role: "gateway"
      upstreamHostCA:
        mount: "ssh-upstream-host"
`

	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(tmpFile, []byte(yaml), 0600)
	require.NoError(t, err)

	cfg, err := Load(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	require.NotNil(t, cfg.SSH)
	require.NotNil(t, cfg.SSH.CA.Vault)
	v := cfg.SSH.CA.Vault

	assert.Equal(t, "ssh-gateway-host", v.GetGatewayHostCAMount())
	assert.Equal(t, "gateway", v.GetGatewayHostCARole())
	assert.Equal(t, "ssh-gateway-user", v.GetGatewayUserCAMount())
	assert.Equal(t, "gateway", v.GetGatewayUserCARole())
	assert.Equal(t, "ssh-upstream-host", v.GetUpstreamHostCAMount())
}

func TestLoad_UseDefaultValues(t *testing.T) {
	yaml := `
twingate:
  network: "acme"
tls:
  certificates:
    files:
      - certificateFile: "tls.crt"
        privateKeyFile: "tls.key"
kubernetes: {}
`

	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(tmpFile, []byte(yaml), 0600)
	require.NoError(t, err)

	cfg, err := Load(tmpFile)
	require.NoError(t, err)

	// Check defaults
	assert.Equal(t, 8443, cfg.Port)
	assert.Equal(t, 9090, cfg.MetricsPort)
	assert.Equal(t, time.Minute*5, cfg.Log.SessionRecording.Segment.MaxDuration)
	assert.Equal(t, 64_000, cfg.Log.SessionRecording.Segment.MaxSize.Bytes())
	assert.Equal(t, zapcore.InfoLevel, cfg.Log.System.Level)
	assert.Equal(t, "twingate.com", cfg.Twingate.Host)
}

func TestLoad_Errors(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		errContains string
	}{
		{
			name:        "invalid yaml syntax",
			yaml:        "invalid: yaml: content:",
			errContains: "failed to parse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := filepath.Join(t.TempDir(), "config.yaml")
			err := os.WriteFile(tmpFile, []byte(tt.yaml), 0600)
			require.NoError(t, err)

			_, err = Load(tmpFile)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		wantErr     bool
		errContains string
	}{
		{
			name: "valid config",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test", Host: "twingate.com"},
				Port:        8443,
				MetricsPort: 9090,
				Log: LogConfig{
					SessionRecording: SessionRecordingConfig{
						Segment: SessionRecordingSegmentConfig{MaxSize: defaultSessionRecordingSegmentMaxSize},
					},
				},
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
				WebApp: &WebAppConfig{
					RequestHeaders: map[string]string{"Authorization": "Bearer {{jwt}}"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid session recording segment limit",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test", Host: "twingate.com"},
				Port:        8443,
				MetricsPort: 9090,
				Log: LogConfig{
					SessionRecording: SessionRecordingConfig{
						Segment: SessionRecordingSegmentConfig{MaxSize: 256_001},
					},
				},
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "log config",
		},
		{
			name: "invalid upstreamTrustedCABundles entry",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test", Host: "twingate.com"},
				Port:        8443,
				MetricsPort: 9090,
				Log: LogConfig{
					SessionRecording: SessionRecordingConfig{
						Segment: SessionRecordingSegmentConfig{MaxSize: defaultSessionRecordingSegmentMaxSize},
					},
				},
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				UpstreamTrustedCABundles: []UpstreamTrustedCABundle{{}},
				Kubernetes:               &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "upstreamTrustedCABundles config",
		},
		{
			name: "missing Twingate network",
			config: &Config{
				Port:        8443,
				MetricsPort: 9090,
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "twingate.network",
		},
		{
			name: "network with digits",
			config: &Config{
				Twingate:    TwingateConfig{Network: "us1", Host: "twingate.com"},
				Port:        8443,
				MetricsPort: 9090,
				Log: LogConfig{
					SessionRecording: SessionRecordingConfig{
						Segment: SessionRecordingSegmentConfig{MaxSize: defaultSessionRecordingSegmentMaxSize},
					},
				},
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr: false,
		},
		{
			name: "network with invalid characters",
			config: &Config{
				Twingate:    TwingateConfig{Network: "evil.com/x", Host: "twingate.com"},
				Port:        8443,
				MetricsPort: 9090,
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "must be 1-63 lowercase alphanumeric characters",
		},
		{
			name: "network with uppercase letters",
			config: &Config{
				Twingate:    TwingateConfig{Network: "ACME", Host: "twingate.com"},
				Port:        8443,
				MetricsPort: 9090,
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "must be 1-63 lowercase alphanumeric characters",
		},
		{
			name: "network with hyphen",
			config: &Config{
				Twingate:    TwingateConfig{Network: "us1-acme", Host: "twingate.com"},
				Port:        8443,
				MetricsPort: 9090,
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "must be 1-63 lowercase alphanumeric characters",
		},
		{
			name: "network at max length",
			config: &Config{
				Twingate:    TwingateConfig{Network: strings.Repeat("a", 63), Host: "twingate.com"},
				Port:        8443,
				MetricsPort: 9090,
				Log: LogConfig{
					SessionRecording: SessionRecordingConfig{
						Segment: SessionRecordingSegmentConfig{MaxSize: defaultSessionRecordingSegmentMaxSize},
					},
				},
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr: false,
		},
		{
			name: "network over max length",
			config: &Config{
				Twingate:    TwingateConfig{Network: strings.Repeat("a", 64), Host: "twingate.com"},
				Port:        8443,
				MetricsPort: 9090,
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "must be 1-63 lowercase alphanumeric characters",
		},
		{
			name: "host with opstg suffix",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test", Host: "foo.stg.opstg.com"},
				Port:        8443,
				MetricsPort: 9090,
				Log: LogConfig{
					SessionRecording: SessionRecordingConfig{
						Segment: SessionRecordingSegmentConfig{MaxSize: defaultSessionRecordingSegmentMaxSize},
					},
				},
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr: false,
		},
		{
			name: "host with test suffix",
			config: &Config{
				Twingate:    TwingateConfig{Network: "acme", Host: "test"},
				Port:        8443,
				MetricsPort: 9090,
				Log: LogConfig{
					SessionRecording: SessionRecordingConfig{
						Segment: SessionRecordingSegmentConfig{MaxSize: defaultSessionRecordingSegmentMaxSize},
					},
				},
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr: false,
		},
		{
			name: "host suffix match is case-insensitive",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test", Host: "Foo.Twingate.COM"},
				Port:        8443,
				MetricsPort: 9090,
				Log: LogConfig{
					SessionRecording: SessionRecordingConfig{
						Segment: SessionRecordingSegmentConfig{MaxSize: defaultSessionRecordingSegmentMaxSize},
					},
				},
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr: false,
		},
		{
			name: "empty host",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test", Host: ""},
				Port:        8443,
				MetricsPort: 9090,
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "invalid twingate.host",
		},
		{
			name: "host with disallowed suffix",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test", Host: "evil.example.com"},
				Port:        8443,
				MetricsPort: 9090,
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "not a trusted Twingate domain",
		},
		{
			name: "host with scheme and path",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test", Host: "https://evil.com/x"},
				Port:        8443,
				MetricsPort: 9090,
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "not a valid hostname",
		},
		{
			name: "host embeds allowed suffix in path",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test", Host: "evil.com/x.twingate.com"},
				Port:        8443,
				MetricsPort: 9090,
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "not a valid hostname",
		},
		{
			name: "host is an IP address",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test", Host: "10.0.0.5"},
				Port:        8443,
				MetricsPort: 9090,
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "not a trusted Twingate domain",
		},
		{
			name: "invalid port",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test", Host: "twingate.com"},
				Port:        -1,
				MetricsPort: 9090,
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "port must be between",
		},
		{
			name: "invalid metrics port",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test", Host: "twingate.com"},
				Port:        8443,
				MetricsPort: 70000,
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
				Kubernetes: &KubernetesConfig{},
			},
			wantErr:     true,
			errContains: "metricsPort must be between",
		},
		{
			name: "no protocols configured",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test", Host: "twingate.com"},
				Port:        8443,
				MetricsPort: 9090,
				Log: LogConfig{
					SessionRecording: SessionRecordingConfig{
						Segment: SessionRecordingSegmentConfig{MaxSize: defaultSessionRecordingSegmentMaxSize},
					},
				},
				TLS: TLSConfig{
					Certificates: &TLSCertificateSources{
						Files: []TLSCertificateFileKeyPair{
							{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "at least one protocol",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLogConfig_Validate(t *testing.T) {
	segment := SessionRecordingSegmentConfig{MaxSize: defaultSessionRecordingSegmentMaxSize}
	twoOutputs := LogOutputConfig{Stderr: &LogStandardErrorConfig{}, Stdout: &LogStandardOutputConfig{}}

	tests := []struct {
		name        string
		log         LogConfig
		wantErr     error
		errContains string
	}{
		{
			name: "no output set",
			log:  LogConfig{SessionRecording: SessionRecordingConfig{Segment: segment}},
		},
		{
			name: "one output per category",
			log: LogConfig{
				System:           LogSystemConfig{Output: LogOutputConfig{Stdout: &LogStandardOutputConfig{}}},
				Audit:            LogAuditConfig{Output: LogOutputConfig{Stderr: &LogStandardErrorConfig{}}},
				SessionRecording: SessionRecordingConfig{Segment: segment, Output: LogOutputConfig{Stdout: &LogStandardOutputConfig{}}},
			},
		},
		{
			name: "one file path per category",
			log: LogConfig{
				Audit:            LogAuditConfig{Output: LogOutputConfig{File: &LogFileOutputConfig{Path: "/var/log/gateway/audit.log"}}},
				SessionRecording: SessionRecordingConfig{Segment: segment, Output: LogOutputConfig{File: &LogFileOutputConfig{Path: "/var/log/gateway/sessions.log"}}},
			},
		},
		{
			name:        "two system outputs",
			log:         LogConfig{System: LogSystemConfig{Output: twoOutputs}, SessionRecording: SessionRecordingConfig{Segment: segment}},
			wantErr:     errMultipleOutputs,
			errContains: "system: output",
		},
		{
			name:        "two audit outputs",
			log:         LogConfig{Audit: LogAuditConfig{Output: twoOutputs}, SessionRecording: SessionRecordingConfig{Segment: segment}},
			wantErr:     errMultipleOutputs,
			errContains: "audit: output",
		},
		{
			name:        "two session recording outputs",
			log:         LogConfig{SessionRecording: SessionRecordingConfig{Segment: segment, Output: twoOutputs}},
			wantErr:     errMultipleOutputs,
			errContains: "sessionRecording: output",
		},
		{
			name: "duplicate file output paths",
			log: LogConfig{
				Audit:            LogAuditConfig{Output: LogOutputConfig{File: &LogFileOutputConfig{Path: "/var/log/gateway/gateway.log"}}},
				SessionRecording: SessionRecordingConfig{Segment: segment, Output: LogOutputConfig{File: &LogFileOutputConfig{Path: "/var/log/gateway/gateway.log"}}},
			},
			wantErr:     errDuplicateLogFilePath,
			errContains: "/var/log/gateway/gateway.log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.log.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.wantErr)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestLogSystemConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		system      LogSystemConfig
		wantErr     error
		errContains string
	}{
		{
			name:   "valid",
			system: LogSystemConfig{Level: zapcore.DebugLevel, Output: LogOutputConfig{Stdout: &LogStandardOutputConfig{}}},
		},
		{
			name:   "level at the upper bound",
			system: LogSystemConfig{Level: zapcore.ErrorLevel},
		},
		{
			name:        "level above the upper bound",
			system:      LogSystemConfig{Level: zapcore.DPanicLevel},
			wantErr:     errUnsupportedLogLevel,
			errContains: "level",
		},
		{
			name:        "two outputs",
			system:      LogSystemConfig{Output: LogOutputConfig{Stderr: &LogStandardErrorConfig{}, Stdout: &LogStandardOutputConfig{}}},
			wantErr:     errMultipleOutputs,
			errContains: "output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.system.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.wantErr)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestLogAuditConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		audit       LogAuditConfig
		wantErr     error
		errContains string
	}{
		{
			name:  "valid",
			audit: LogAuditConfig{Output: LogOutputConfig{Stderr: &LogStandardErrorConfig{}}},
		},
		{
			name:        "two outputs",
			audit:       LogAuditConfig{Output: LogOutputConfig{Stderr: &LogStandardErrorConfig{}, Stdout: &LogStandardOutputConfig{}}},
			wantErr:     errMultipleOutputs,
			errContains: "output",
		},
		{
			name:        "invalid file output",
			audit:       LogAuditConfig{Output: LogOutputConfig{File: &LogFileOutputConfig{}}},
			wantErr:     ErrRequired,
			errContains: "output: file: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.audit.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.wantErr)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestSessionRecordingConfig_Validate(t *testing.T) {
	segment := SessionRecordingSegmentConfig{MaxSize: defaultSessionRecordingSegmentMaxSize}

	tests := []struct {
		name             string
		sessionRecording SessionRecordingConfig
		wantErr          error
		errContains      string
	}{
		{
			name:             "valid",
			sessionRecording: SessionRecordingConfig{Segment: segment, Output: LogOutputConfig{Stdout: &LogStandardOutputConfig{}}},
		},
		{
			name:             "invalid segment",
			sessionRecording: SessionRecordingConfig{Segment: SessionRecordingSegmentConfig{MaxSize: 0}},
			wantErr:          errSizeOutOfRange,
			errContains:      "segment",
		},
		{
			name:             "two outputs",
			sessionRecording: SessionRecordingConfig{Segment: segment, Output: LogOutputConfig{Stderr: &LogStandardErrorConfig{}, Stdout: &LogStandardOutputConfig{}}},
			wantErr:          errMultipleOutputs,
			errContains:      "output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sessionRecording.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.wantErr)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestSessionRecordingSegmentConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		segment     SessionRecordingSegmentConfig
		wantErr     error
		errContains string
	}{
		{
			name:    "valid",
			segment: SessionRecordingSegmentConfig{MaxDuration: 5 * time.Minute, MaxSize: 64_000},
		},
		{
			name:    "maxSize at the upper bound",
			segment: SessionRecordingSegmentConfig{MaxSize: 256_000},
		},
		{
			name:        "negative maxDuration",
			segment:     SessionRecordingSegmentConfig{MaxDuration: -1 * time.Minute, MaxSize: 64_000},
			wantErr:     errNegativeDuration,
			errContains: "maxDuration",
		},
		{
			name:        "zero maxSize",
			segment:     SessionRecordingSegmentConfig{MaxDuration: 5 * time.Minute, MaxSize: 0},
			wantErr:     errSizeOutOfRange,
			errContains: "maxSize",
		},
		{
			name:        "maxSize above the upper bound",
			segment:     SessionRecordingSegmentConfig{MaxDuration: 5 * time.Minute, MaxSize: 256_001},
			wantErr:     errSizeOutOfRange,
			errContains: "maxSize",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.segment.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.wantErr)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestLogFileOutputConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		file        LogFileOutputConfig
		wantErr     error
		errContains string
	}{
		{
			name: "valid",
			file: LogFileOutputConfig{Path: "/var/log/gateway/audit.log"},
		},
		{
			name:        "missing path",
			file:        LogFileOutputConfig{},
			wantErr:     ErrRequired,
			errContains: "path",
		},
		{
			name:        "invalid rotation",
			file:        LogFileOutputConfig{Path: "/var/log/gateway/audit.log", Rotation: LogFileRotationConfig{MaxBackupFiles: -1}},
			wantErr:     errNegativeCount,
			errContains: "rotation: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.file.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.wantErr)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestLogFileRotationConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		rotation    LogFileRotationConfig
		wantErr     error
		errContains string
	}{
		{
			name:     "every field omitted",
			rotation: LogFileRotationConfig{},
		},
		{
			name:     "valid",
			rotation: LogFileRotationConfig{MaxSize: 100_000_000, MaxBackupFiles: 3, MaxAge: new(yamlutil.Duration(7 * 24 * time.Hour)), Compression: "none"},
		},
		{
			name:     "gzip compression",
			rotation: LogFileRotationConfig{Compression: "gzip"},
		},
		{
			name:     "zstd compression",
			rotation: LogFileRotationConfig{Compression: "zstd"},
		},
		{
			name:        "negative maxSize",
			rotation:    LogFileRotationConfig{MaxSize: -1},
			wantErr:     errNegativeSize,
			errContains: "maxSize",
		},
		{
			name:        "negative maxBackupFiles",
			rotation:    LogFileRotationConfig{MaxBackupFiles: -1},
			wantErr:     errNegativeCount,
			errContains: "maxBackupFiles",
		},
		{
			name:     "maxAge at the upper bound",
			rotation: LogFileRotationConfig{MaxAge: new(yamlutil.Duration(3650 * 24 * time.Hour))},
		},
		{
			name:        "maxAge above the upper bound",
			rotation:    LogFileRotationConfig{MaxAge: new(yamlutil.Duration(3650*24*time.Hour + 1))},
			wantErr:     errDurationTooLong,
			errContains: "maxAge",
		},
		{
			name:        "unsupported compression",
			rotation:    LogFileRotationConfig{Compression: "lz4"},
			wantErr:     errUnsupportedCompression,
			errContains: "compression",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rotation.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.wantErr)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestLogFileRotationConfig_GetMaxSize(t *testing.T) {
	tests := []struct {
		name    string
		maxSize yamlutil.ByteSize
		want    int
	}{
		{name: "omitted uses the 100MB default", maxSize: 0, want: 100},
		{name: "1MB is 1", maxSize: 1_000_000, want: 1},
		{name: "just over 1MB rounds up to 2", maxSize: 1_000_001, want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rotation := LogFileRotationConfig{MaxSize: tt.maxSize}

			assert.Equal(t, tt.want, rotation.GetMaxSize())
		})
	}
}

func TestLogFileRotationConfig_GetMaxBackupFiles(t *testing.T) {
	assert.Equal(t, 3, (&LogFileRotationConfig{}).GetMaxBackupFiles())
	assert.Equal(t, 5, (&LogFileRotationConfig{MaxBackupFiles: 5}).GetMaxBackupFiles())
}

func TestLogFileRotationConfig_GetMaxAge(t *testing.T) {
	tests := []struct {
		name   string
		maxAge *yamlutil.Duration
		want   int
	}{
		{name: "omitted uses the 7-day default", maxAge: nil, want: 7},
		{name: "explicit zero turns the age limit off", maxAge: new(yamlutil.Duration(0)), want: 0},
		{name: "36h rounds up to 2 days", maxAge: new(yamlutil.Duration(36 * time.Hour)), want: 2},
		{name: "whole days are kept", maxAge: new(yamlutil.Duration(7 * 24 * time.Hour)), want: 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rotation := LogFileRotationConfig{MaxAge: tt.maxAge}

			assert.Equal(t, tt.want, rotation.GetMaxAge())
		})
	}
}

func TestLogFileRotationConfig_GetCompression(t *testing.T) {
	assert.Equal(t, "none", (&LogFileRotationConfig{}).GetCompression())
	assert.Equal(t, "gzip", (&LogFileRotationConfig{Compression: "gzip"}).GetCompression())
}

func TestTLSConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		tls         TLSConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid",
			tls: TLSConfig{
				Certificates: &TLSCertificateSources{
					Files: []TLSCertificateFileKeyPair{
						{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
					},
				},
				Automation: &TLSAutomationConfig{
					Issuer: TLSIssuerConfig{
						Local: &TLSLocalIssuerConfig{CertificateFile: "ca.crt", PrivateKeyFile: "ca.key"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "certificates only",
			tls: TLSConfig{
				Certificates: &TLSCertificateSources{
					Files: []TLSCertificateFileKeyPair{
						{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
					},
				},
			},
			wantErr: false,
		},
		{
			name:        "missing certificates and automation",
			tls:         TLSConfig{},
			wantErr:     true,
			errContains: "either 'certificates' or 'automation' must be specified for TLS config",
		},
		{
			name:        "invalid certificates",
			tls:         TLSConfig{Certificates: &TLSCertificateSources{}},
			wantErr:     true,
			errContains: "certificates: required field is missing: files",
		},
		{
			name:        "invalid automation",
			tls:         TLSConfig{Automation: &TLSAutomationConfig{}},
			wantErr:     true,
			errContains: "automation: issuer: at least one TLS issuer must be configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tls.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTLSCertificateSources_Validate(t *testing.T) {
	tests := []struct {
		name        string
		sources     TLSCertificateSources
		wantErr     bool
		errContains string
	}{
		{
			name: "multiple files",
			sources: TLSCertificateSources{
				Files: []TLSCertificateFileKeyPair{
					{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
					{CertificateFile: "other.crt", PrivateKeyFile: "other.key"},
				},
			},
			wantErr: false,
		},
		{
			name:        "no files",
			sources:     TLSCertificateSources{},
			wantErr:     true,
			errContains: "required field is missing: files",
		},
		{
			name: "file missing certificate",
			sources: TLSCertificateSources{
				Files: []TLSCertificateFileKeyPair{
					{PrivateKeyFile: "tls.key"},
				},
			},
			wantErr:     true,
			errContains: "files[0]: required field is missing: certificateFile",
		},
		{
			name: "file missing private key",
			sources: TLSCertificateSources{
				Files: []TLSCertificateFileKeyPair{
					{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
					{CertificateFile: "other.crt"},
				},
			},
			wantErr:     true,
			errContains: "files[1]: required field is missing: privateKeyFile",
		},
		{
			name: "duplicate certificate file",
			sources: TLSCertificateSources{
				Files: []TLSCertificateFileKeyPair{
					{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
					{CertificateFile: "tls.crt", PrivateKeyFile: "other.key"},
				},
			},
			wantErr:     true,
			errContains: `duplicate certificateFile: "tls.crt"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sources.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTLSAutomationConfig_Validate(t *testing.T) {
	localIssuer := TLSIssuerConfig{
		Local: &TLSLocalIssuerConfig{CertificateFile: "ca.crt", PrivateKeyFile: "ca.key"},
	}

	tests := []struct {
		name        string
		automation  TLSAutomationConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid with full certificate config",
			automation: TLSAutomationConfig{
				Issuer: localIssuer,
				Certificate: TLSAutomationCertificateConfig{
					TTL: 48 * time.Hour,
					Key: TLSCertificateKeyConfig{Type: "rsa", Bits: 4096},
				},
			},
			wantErr: false,
		},
		{
			name:       "valid with defaults",
			automation: TLSAutomationConfig{Issuer: localIssuer},
			wantErr:    false,
		},
		{
			name: "valid with vault issuer",
			automation: TLSAutomationConfig{
				Issuer: TLSIssuerConfig{Vault: &TLSVaultIssuerConfig{
					Address: "https://vault:8200",
					Role:    "gateway",
				}},
			},
			wantErr: false,
		},
		{
			name: "valid with gcpPrivateCA issuer",
			automation: TLSAutomationConfig{
				Issuer: TLSIssuerConfig{GCPPrivateCA: &TLSGCPPrivateCAIssuerConfig{
					Project:  "acme",
					Location: "us-east1",
					CAPoolID: "gateway",
				}},
				Certificate: TLSAutomationCertificateConfig{CommonName: "gateway.acme.int"},
			},
			wantErr: false,
		},
		{
			name: "gcpPrivateCA issuer missing common name",
			automation: TLSAutomationConfig{
				Issuer: TLSIssuerConfig{GCPPrivateCA: &TLSGCPPrivateCAIssuerConfig{
					Project:  "acme",
					Location: "us-east1",
					CAPoolID: "gateway",
				}},
			},
			wantErr:     true,
			errContains: "certificate: required field is missing: commonName is required for gcpPrivateCA issuer",
		},
		{
			name: "conflicting local, vault and gcpPrivateCA issuers",
			automation: TLSAutomationConfig{
				Issuer: TLSIssuerConfig{
					Local:        localIssuer.Local,
					Vault:        &TLSVaultIssuerConfig{Address: "https://vault:8200", Role: "gateway"},
					GCPPrivateCA: &TLSGCPPrivateCAIssuerConfig{Project: "acme", Location: "us-east1", CAPoolID: "gateway"},
				},
			},
			wantErr:     true,
			errContains: "issuer: only one of 'local', 'vault' or 'gcpPrivateCA' can be specified",
		},
		{
			name: "vault issuer missing address",
			automation: TLSAutomationConfig{
				Issuer: TLSIssuerConfig{Vault: &TLSVaultIssuerConfig{Role: "gateway"}},
			},
			wantErr:     true,
			errContains: "issuer: vault: required field is missing: address",
		},
		{
			name: "invalid gcpPrivateCA issuer",
			automation: TLSAutomationConfig{
				Issuer: TLSIssuerConfig{GCPPrivateCA: &TLSGCPPrivateCAIssuerConfig{Location: "us-east1", CAPoolID: "gateway"}},
			},
			wantErr:     true,
			errContains: "issuer: gcpPrivateCA: required field is missing: project",
		},
		{
			name:        "missing issuer",
			automation:  TLSAutomationConfig{},
			wantErr:     true,
			errContains: "issuer: at least one TLS issuer must be configured",
		},
		{
			name: "local issuer missing certificate",
			automation: TLSAutomationConfig{
				Issuer: TLSIssuerConfig{Local: &TLSLocalIssuerConfig{PrivateKeyFile: "ca.key"}},
			},
			wantErr:     true,
			errContains: "issuer: local: required field is missing: certificateFile",
		},
		{
			name: "local issuer missing private key",
			automation: TLSAutomationConfig{
				Issuer: TLSIssuerConfig{Local: &TLSLocalIssuerConfig{CertificateFile: "ca.crt"}},
			},
			wantErr:     true,
			errContains: "issuer: local: required field is missing: privateKeyFile",
		},
		{
			name: "ttl at the minimum",
			automation: TLSAutomationConfig{
				Issuer:      localIssuer,
				Certificate: TLSAutomationCertificateConfig{TTL: minTLSCertificateTTL},
			},
			wantErr: false,
		},
		{
			name: "negative ttl",
			automation: TLSAutomationConfig{
				Issuer:      localIssuer,
				Certificate: TLSAutomationCertificateConfig{TTL: -time.Hour},
			},
			wantErr:     true,
			errContains: "certificate: TTL must be non-negative: ttl",
		},
		{
			name: "ttl below the minimum",
			automation: TLSAutomationConfig{
				Issuer:      localIssuer,
				Certificate: TLSAutomationCertificateConfig{TTL: minTLSCertificateTTL - time.Second},
			},
			wantErr:     true,
			errContains: "certificate: TTL is too short: TTL must be at least 10m0s",
		},
		{
			name: "invalid key type",
			automation: TLSAutomationConfig{
				Issuer:      localIssuer,
				Certificate: TLSAutomationCertificateConfig{Key: TLSCertificateKeyConfig{Type: "ed25519"}},
			},
			wantErr:     true,
			errContains: "certificate: key: invalid TLS key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.automation.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTLSVaultIssuerConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         TLSVaultIssuerConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid",
			cfg:  TLSVaultIssuerConfig{VaultConfig: VaultConfig{Address: "https://vault:8200"}, Role: "gateway"},
		},
		{
			name:        "missing address",
			cfg:         TLSVaultIssuerConfig{Role: "gateway"},
			wantErr:     true,
			errContains: "required field is missing: address",
		},
		{
			name:        "missing role",
			cfg:         TLSVaultIssuerConfig{VaultConfig: VaultConfig{Address: "https://vault:8200"}},
			wantErr:     true,
			errContains: "required field is missing: role",
		},
		{
			name: "conflicting auth",
			cfg: TLSVaultIssuerConfig{
				VaultConfig: VaultConfig{
					Address: "https://vault:8200",
					Auth:    VaultAuthConfig{Token: "token", GCP: &VaultGCPConfig{Role: "role", Type: "gce"}},
				},
				Role: "gateway",
			},
			wantErr:     true,
			errContains: "auth: only one of 'token', 'appRole', 'gcp', or 'aws' can be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTLSVaultIssuerConfig_GetMount(t *testing.T) {
	assert.Equal(t, "pki", (&TLSVaultIssuerConfig{}).GetMount())
	assert.Equal(t, "pki-int", (&TLSVaultIssuerConfig{Mount: "pki-int"}).GetMount())
}

func TestTLSGCPPrivateCAIssuerConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         TLSGCPPrivateCAIssuerConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid",
			cfg:  TLSGCPPrivateCAIssuerConfig{Project: "acme", Location: "us-east1", CAPoolID: "gateway"},
		},
		{
			name:        "missing project",
			cfg:         TLSGCPPrivateCAIssuerConfig{Location: "us-east1", CAPoolID: "gateway"},
			wantErr:     true,
			errContains: "required field is missing: project",
		},
		{
			name:        "missing location",
			cfg:         TLSGCPPrivateCAIssuerConfig{Project: "acme", CAPoolID: "gateway"},
			wantErr:     true,
			errContains: "required field is missing: location",
		},
		{
			name:        "missing CA pool",
			cfg:         TLSGCPPrivateCAIssuerConfig{Project: "acme", Location: "us-east1"},
			wantErr:     true,
			errContains: "required field is missing: caPoolID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestKubernetesConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		k8s         KubernetesConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid with external upstream",
			k8s: KubernetesConfig{
				Upstreams: []KubernetesUpstream{
					{Name: "k8s", BearerToken: "token"},
				},
			},
			wantErr: false,
		},
		{
			name: "no upstreams is allowed (in-cluster default)",
			k8s: KubernetesConfig{
				Upstreams: []KubernetesUpstream{},
			},
			wantErr: false,
		},
		{
			name: "duplicate upstream names",
			k8s: KubernetesConfig{
				Upstreams: []KubernetesUpstream{
					{Name: "prod-k8s", BearerToken: "token"},
					{Name: "prod-k8s", BearerToken: "token"},
				},
			},
			wantErr:     true,
			errContains: "\"prod-k8s\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.k8s.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateUpstreamTrustedCABundles(t *testing.T) {
	tests := []struct {
		name        string
		caBundles   []UpstreamTrustedCABundle
		wantErr     bool
		errContains string
	}{
		{
			name: "valid list",
			caBundles: []UpstreamTrustedCABundle{
				{File: "/etc/gateway/ca1.crt"},
				{File: "/etc/gateway/ca2.crt"},
			},
			wantErr: false,
		},
		{
			name:      "empty list is allowed",
			caBundles: []UpstreamTrustedCABundle{},
			wantErr:   false,
		},
		{
			name:        "missing file",
			caBundles:   []UpstreamTrustedCABundle{{}},
			wantErr:     true,
			errContains: "upstreamTrustedCABundles[0]: required field is missing: file",
		},
		{
			name: "duplicate file",
			caBundles: []UpstreamTrustedCABundle{
				{File: "/etc/gateway/ca.crt"},
				{File: "/etc/gateway/ca.crt"},
			},
			wantErr:     true,
			errContains: "\"/etc/gateway/ca.crt\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUpstreamTrustedCABundles(tt.caBundles)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLoad_UpstreamTrustedCABundles(t *testing.T) {
	yaml := `
twingate:
  network: "acme"
tls:
  certificates:
    files:
      - certificateFile: "tls.crt"
        privateKeyFile: "tls.key"
upstreamTrustedCABundles:
  - file: "/etc/gateway/ca1.crt"
  - file: "/etc/gateway/ca2.crt"
webApp: {}
`

	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(tmpFile, []byte(yaml), 0600)
	require.NoError(t, err)

	cfg, err := Load(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	want := []UpstreamTrustedCABundle{
		{File: "/etc/gateway/ca1.crt"},
		{File: "/etc/gateway/ca2.crt"},
	}
	assert.Equal(t, want, cfg.UpstreamTrustedCABundles)
	require.NoError(t, cfg.Validate())
}

func TestKubernetesUpstream_Validate(t *testing.T) {
	tests := []struct {
		name        string
		upstream    KubernetesUpstream
		wantErr     bool
		errContains string
	}{
		{
			name: "valid with token",
			upstream: KubernetesUpstream{
				Name:        "k8s",
				BearerToken: "token",
			},
			wantErr: false,
		},
		{
			name: "valid with token file",
			upstream: KubernetesUpstream{
				Name:            "k8s",
				BearerTokenFile: "/path/to/token",
			},
			wantErr: false,
		},
		{
			name:        "missing name",
			upstream:    KubernetesUpstream{BearerToken: "token"},
			wantErr:     true,
			errContains: "name",
		},
		{
			name:        "missing auth",
			upstream:    KubernetesUpstream{Name: "k8s"},
			wantErr:     true,
			errContains: "bearerToken or bearerTokenFile is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.upstream.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSSHConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		ssh         SSHConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "missing CA config",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username: "gateway",
					Key: SSHKeyConfig{
						Type: "rsa",
						Bits: 2048,
					},
				},
				CA: SSHCAConfig{},
			},
			wantErr:     true,
			errContains: "either 'local' or 'vault' must be specified",
		},
		{
			name: "valid with local CA",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username:        "gateway",
					Key:             SSHKeyConfig{Type: "ed25519"},
					HostCertificate: SSHCertificateConfig{TTL: 24 * time.Hour},
					UserCertificate: SSHCertificateConfig{TTL: 5 * time.Minute},
				},
				CA: SSHCAConfig{
					Local: &SSHCALocalConfig{
						PrivateKeyFile: "ca.key",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid with Vault CA",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username: "gateway",
				},
				CA: SSHCAConfig{
					Vault: &SSHCAVaultConfig{
						Address: "https://vault:8200",
						Role:    "gateway",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid key type",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username: "gateway",
					Key:      SSHKeyConfig{Type: "invalid-type"},
				},
			},
			wantErr:     true,
			errContains: "invalid SSH key type",
		},
		{
			name: "conflicting CA config - both local and Vault",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username: "gateway",
					Key:      SSHKeyConfig{Type: "ed25519"},
				},
				CA: SSHCAConfig{
					Local: &SSHCALocalConfig{
						PrivateKeyFile: "ca.key",
					},
					Vault: &SSHCAVaultConfig{
						Address: "https://vault:8200",
						Role:    "gateway",
					},
				},
			},
			wantErr:     true,
			errContains: "only one of 'local' or 'vault'",
		},
		{
			name: "local CA missing private key file",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username: "gateway",
				},
				CA: SSHCAConfig{
					Local: &SSHCALocalConfig{},
				},
			},
			wantErr:     true,
			errContains: "privateKeyFile",
		},
		{
			name: "Vault CA missing address",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username: "gateway",
				},
				CA: SSHCAConfig{
					Vault: &SSHCAVaultConfig{
						Role: "gateway",
					},
				},
			},
			wantErr:     true,
			errContains: "address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ssh.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSSHCAVaultConfig_EffectiveMountAndRole(t *testing.T) {
	tests := []struct {
		name                  string
		cfg                   *SSHCAVaultConfig
		wantGatewayHostMount  string
		wantGatewayHostRole   string
		wantGatewayUserMount  string
		wantGatewayUserRole   string
		wantUpstreamHostMount string
	}{
		{
			name:                  "default mounts and empty roles",
			cfg:                   &SSHCAVaultConfig{},
			wantGatewayHostMount:  "ssh",
			wantGatewayHostRole:   "",
			wantGatewayUserMount:  "ssh",
			wantGatewayUserRole:   "",
			wantUpstreamHostMount: "ssh",
		},
		{
			name: "top-level mount/role",
			cfg: &SSHCAVaultConfig{
				Mount: "ssh-default",
				Role:  "gateway",
			},
			wantGatewayHostMount:  "ssh-default",
			wantGatewayHostRole:   "gateway",
			wantGatewayUserMount:  "ssh-default",
			wantGatewayUserRole:   "gateway",
			wantUpstreamHostMount: "ssh-default",
		},
		{
			name: "per-CA overrides win",
			cfg: &SSHCAVaultConfig{
				Mount: "ssh-default",
				Role:  "gateway",
				GatewayHostCA: &SSHCAVaultCertConfig{
					Mount: "ssh-gateway-host",
					Role:  "host-override",
				},
				GatewayUserCA: &SSHCAVaultCertConfig{
					Mount: "ssh-gateway-user",
					Role:  "user-override",
				},
				UpstreamHostCA: &SSHCAVaultMountConfig{
					Mount: "ssh-upstream-host",
				},
			},
			wantGatewayHostMount:  "ssh-gateway-host",
			wantGatewayHostRole:   "host-override",
			wantGatewayUserMount:  "ssh-gateway-user",
			wantGatewayUserRole:   "user-override",
			wantUpstreamHostMount: "ssh-upstream-host",
		},
		{
			name: "partial override falls back to top-level",
			cfg: &SSHCAVaultConfig{
				Mount: "ssh-default",
				Role:  "gateway",
				GatewayHostCA: &SSHCAVaultCertConfig{
					Mount: "ssh-gateway-host",
				},
			},
			wantGatewayHostMount:  "ssh-gateway-host",
			wantGatewayHostRole:   "gateway",
			wantGatewayUserMount:  "ssh-default",
			wantGatewayUserRole:   "gateway",
			wantUpstreamHostMount: "ssh-default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantGatewayHostMount, tt.cfg.GetGatewayHostCAMount())
			assert.Equal(t, tt.wantGatewayHostRole, tt.cfg.GetGatewayHostCARole())
			assert.Equal(t, tt.wantGatewayUserMount, tt.cfg.GetGatewayUserCAMount())
			assert.Equal(t, tt.wantGatewayUserRole, tt.cfg.GetGatewayUserCARole())
			assert.Equal(t, tt.wantUpstreamHostMount, tt.cfg.GetUpstreamHostCAMount())
		})
	}
}

func TestSSHCAVaultConfig_Validate(t *testing.T) {
	t.Run("missing address", func(t *testing.T) {
		cfg := &SSHCAVaultConfig{Role: "gateway"}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "address")
	})

	t.Run("missing role (no override roles)", func(t *testing.T) {
		cfg := &SSHCAVaultConfig{Address: "https://vault:8200"}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "role is required")
	})

	t.Run("valid with top-level role", func(t *testing.T) {
		cfg := &SSHCAVaultConfig{Address: "https://vault:8200", Role: "gateway"}
		require.NoError(t, cfg.Validate())
	})

	t.Run("valid with per-CA roles only", func(t *testing.T) {
		cfg := &SSHCAVaultConfig{
			Address: "https://vault:8200",
			GatewayHostCA: &SSHCAVaultCertConfig{
				Role: "gateway-host",
			},
			GatewayUserCA: &SSHCAVaultCertConfig{
				Role: "gateway-user",
			},
		}
		require.NoError(t, cfg.Validate())
	})
}

func TestVaultAuthConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         VaultAuthConfig
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid token",
			cfg:     VaultAuthConfig{Token: "token"},
			wantErr: false,
		},
		{
			name: "valid appRole",
			cfg: VaultAuthConfig{
				AppRole: &VaultAppRoleConfig{
					RoleID:       "role-id",
					SecretIDFile: "/path/to/secret-id",
				},
			},
			wantErr: false,
		},
		{
			name: "valid GCP",
			cfg: VaultAuthConfig{
				GCP: &VaultGCPConfig{
					Role: "my-role",
					Type: "gce",
				},
			},
			wantErr: false,
		},
		{
			name: "valid AWS",
			cfg: VaultAuthConfig{
				AWS: &VaultAWSConfig{
					Role: "my-role",
					Type: "iam",
				},
			},
			wantErr: false,
		},
		{
			name:    "valid with empty token (uses VAULT_TOKEN env)",
			cfg:     VaultAuthConfig{},
			wantErr: false,
		},
		{
			name: "conflicting config - both token and appRole",
			cfg: VaultAuthConfig{
				Token: "token",
				AppRole: &VaultAppRoleConfig{
					RoleID:       "role-id",
					SecretIDFile: "/path/to/secret-id",
				},
			},
			wantErr:     true,
			errContains: "only one of 'token', 'appRole', 'gcp', or 'aws'",
		},
		{
			name: "conflicting config - both token and gcp",
			cfg: VaultAuthConfig{
				Token: "token",
				GCP: &VaultGCPConfig{
					Role: "my-role",
					Type: "gce",
				},
			},
			wantErr:     true,
			errContains: "only one of 'token', 'appRole', 'gcp', or 'aws'",
		},
		{
			name: "conflicting config - both aws and gcp",
			cfg: VaultAuthConfig{
				AWS: &VaultAWSConfig{
					Role: "my-role",
					Type: "iam",
				},
				GCP: &VaultGCPConfig{
					Role: "my-role",
					Type: "gce",
				},
			},
			wantErr:     true,
			errContains: "only one of 'token', 'appRole', 'gcp', or 'aws'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestVaultAppRoleConfig_GetMount(t *testing.T) {
	t.Run("default mount", func(t *testing.T) {
		cfg := &VaultAppRoleConfig{
			RoleID:       "role-id",
			SecretIDFile: "/path/to/secret-id",
		}
		assert.Equal(t, "approle", cfg.GetMount())
	})

	t.Run("custom mount", func(t *testing.T) {
		cfg := &VaultAppRoleConfig{
			Mount:        "custom-approle",
			RoleID:       "role-id",
			SecretIDFile: "/path/to/secret-id",
		}
		assert.Equal(t, "custom-approle", cfg.GetMount())
	})
}

func TestVaultAppRoleConfig_Validate(t *testing.T) {
	t.Run("missing roleId", func(t *testing.T) {
		cfg := &VaultAppRoleConfig{
			SecretIDFile: "/path/to/secret-id",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "roleID")
	})

	t.Run("missing both secretID and secretIDFile", func(t *testing.T) {
		cfg := &VaultAppRoleConfig{
			RoleID: "role-id",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "either secretID or secretIDFile is required")
	})

	t.Run("valid with secretID", func(t *testing.T) {
		cfg := &VaultAppRoleConfig{
			RoleID:   "role-id",
			SecretID: "my-secret-id",
		}
		require.NoError(t, cfg.Validate())
	})

	t.Run("valid with secretIDFile", func(t *testing.T) {
		cfg := &VaultAppRoleConfig{
			RoleID:       "role-id",
			SecretIDFile: "/path/to/secret-id",
		}
		require.NoError(t, cfg.Validate())
	})

	t.Run("conflicting secretID and secretIDFile", func(t *testing.T) {
		cfg := &VaultAppRoleConfig{
			RoleID:       "role-id",
			SecretID:     "my-secret-id",
			SecretIDFile: "/path/to/secret-id",
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, ErrConflictingSecretIDConfig)
	})
}

func TestVaultGCPConfig_GetMount(t *testing.T) {
	t.Run("default mount", func(t *testing.T) {
		cfg := &VaultGCPConfig{
			Role: "my-role",
			Type: "gce",
		}
		assert.Equal(t, "gcp", cfg.GetMount())
	})

	t.Run("custom mount", func(t *testing.T) {
		cfg := &VaultGCPConfig{
			Mount: "custom-gcp",
			Role:  "my-role",
			Type:  "gce",
		}
		assert.Equal(t, "custom-gcp", cfg.GetMount())
	})
}

func TestVaultGCPConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *VaultGCPConfig
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid GCE",
			cfg:     &VaultGCPConfig{Role: "my-role", Type: "gce"},
			wantErr: false,
		},
		{
			name:    "valid IAM",
			cfg:     &VaultGCPConfig{Role: "my-role", Type: "iam", ServiceAccountEmail: "gateway-sa@project.iam.gserviceaccount.com"},
			wantErr: false,
		},
		{
			name:    "valid GCE type case insensitive",
			cfg:     &VaultGCPConfig{Role: "my-role", Type: "GCE"},
			wantErr: false,
		},
		{
			name:        "missing role",
			cfg:         &VaultGCPConfig{Type: "gce"},
			wantErr:     true,
			errContains: "role",
		},
		{
			name:        "missing type",
			cfg:         &VaultGCPConfig{Role: "my-role"},
			wantErr:     true,
			errContains: "type",
		},
		{
			name:        "invalid type",
			cfg:         &VaultGCPConfig{Role: "my-role", Type: "invalid"},
			wantErr:     true,
			errContains: "gcp type must be 'gce' or 'iam'",
		},
		{
			name:        "IAM type missing serviceAccountEmail",
			cfg:         &VaultGCPConfig{Role: "my-role", Type: "iam"},
			wantErr:     true,
			errContains: "serviceAccountEmail is required for iam type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestVaultAWSConfig_GetMount(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *VaultAWSConfig
		expected string
	}{
		{
			name: "default mount",
			cfg: &VaultAWSConfig{
				Role: "my-role",
				Type: "iam",
			},
			expected: "aws",
		},
		{
			name: "custom mount",
			cfg: &VaultAWSConfig{
				Mount: "custom-aws",
				Role:  "my-role",
				Type:  "iam",
			},
			expected: "custom-aws",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.cfg.GetMount())
		})
	}
}

func TestVaultAWSConfig_GetSignatureType(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *VaultAWSConfig
		expected string
	}{
		{
			name:     "default to rsa2048 when unset",
			cfg:      &VaultAWSConfig{Role: "my-role", Type: "ec2"},
			expected: "rsa2048",
		},
		{
			name:     "explicit value preserved",
			cfg:      &VaultAWSConfig{Role: "my-role", Type: "ec2", SignatureType: "identity"},
			expected: "identity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.cfg.GetSignatureType())
		})
	}
}

func TestVaultAWSConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *VaultAWSConfig
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid IAM",
			cfg:     &VaultAWSConfig{Role: "my-role", Type: "iam"},
			wantErr: false,
		},
		{
			name:    "valid EC2",
			cfg:     &VaultAWSConfig{Role: "my-role", Type: "ec2"},
			wantErr: false,
		},
		{
			name:    "valid EC2 with signatureType and nonce",
			cfg:     &VaultAWSConfig{Role: "my-role", Type: "ec2", SignatureType: "identity", Nonce: "my-nonce"},
			wantErr: false,
		},
		{
			name:    "Valid IAM case insensitive type",
			cfg:     &VaultAWSConfig{Role: "my-role", Type: "IAM"},
			wantErr: false,
		},
		{
			name:        "missing role",
			cfg:         &VaultAWSConfig{Type: "iam"},
			wantErr:     true,
			errContains: "role",
		},
		{
			name:        "missing type",
			cfg:         &VaultAWSConfig{Role: "my-role"},
			wantErr:     true,
			errContains: "type",
		},
		{
			name:        "invalid type",
			cfg:         &VaultAWSConfig{Role: "my-role", Type: "invalid"},
			wantErr:     true,
			errContains: "aws type must be 'iam' or 'ec2'",
		},
		{
			name:        "invalid signatureType",
			cfg:         &VaultAWSConfig{Role: "my-role", Type: "ec2", SignatureType: "invalid"},
			wantErr:     true,
			errContains: "aws signatureType must be 'identity', 'pkcs7', or 'rsa2048'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
