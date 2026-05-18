// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractHost(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		network  string
		expected string
	}{
		{name: "sharded host", hostname: "acme.us1.test.com", network: "acme", expected: "us1.test.com"},
		{name: "non-sharded host", hostname: "acme.test.com", network: "acme", expected: "test.com"},
		{name: "no network prefix", hostname: "test.com", network: "acme", expected: "test.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractHost(tt.hostname, tt.network))
		})
	}
}

func TestResolveTwingateHostname(t *testing.T) {
	t.Run("follows redirect and returns final hostname", func(t *testing.T) {
		shardServerCalled := false

		shardServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			shardServerCalled = true

			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(shardServer.Close)

		redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, shardServer.URL+r.URL.Path, http.StatusPermanentRedirect)
		}))
		t.Cleanup(redirectServer.Close)

		result := resolveTwingateHostname(redirectServer.URL+"/api/v1/jwk/ec", "test.com", 5*time.Second, 0)

		assert.True(t, shardServerCalled)
		assert.Equal(t, "127.0.0.1", result)
	})

	t.Run("returns server hostname when no redirect", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)

		result := resolveTwingateHostname(server.URL+"/api/v1/jwk/ec", "test.com", 5*time.Second, 0)

		assert.Equal(t, "127.0.0.1", result)
	})

	t.Run("returns default host on connection error", func(t *testing.T) {
		result := resolveTwingateHostname("http://127.0.0.1:1/api/v1/jwk/ec", "test.com", 2*time.Second, 0)

		assert.Equal(t, "test.com", result)
	})
}

func TestLoad_Kubernetes(t *testing.T) {
	yaml := `
twingate:
  network: "acme"
port: 8443
metricsPort: 9090
auditLog:
  flushInterval: "10m"
  flushSizeThreshold: 1000000
tls:
  certificateFile: "tls.crt"
  privateKeyFile: "tls.key"
kubernetes:
  upstreams:
    - name: "k8s-cluster"
      inCluster: true
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

	// Verify Kubernetes upstream parsed correctly
	require.NotNil(t, cfg.Kubernetes)
	assert.Len(t, cfg.Kubernetes.Upstreams, 1)
	assert.Nil(t, cfg.SSH)
	assert.Equal(t, "k8s-cluster", cfg.Kubernetes.Upstreams[0].Name)
	assert.True(t, cfg.Kubernetes.Upstreams[0].InCluster)
}

func TestLoad_SSH(t *testing.T) {
	yaml := `
twingate:
  network: "acme"
port: 8443
metricsPort: 9090
auditLog:
  flushInterval: "10m"
  flushSizeThreshold: 1000000
tls:
  certificateFile: "tls.crt"
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
    manual:
      privateKeyFile: "ca.key"
  upstreams:
    - name: "ssh-server"
      address: "10.0.0.1:22"
`

	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(tmpFile, []byte(yaml), 0600)
	require.NoError(t, err)

	cfg, err := Load(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify SSH upstream parsed correctly
	assert.Nil(t, cfg.Kubernetes)
	require.NotNil(t, cfg.SSH)
	assert.Len(t, cfg.SSH.Upstreams, 1)
	assert.Equal(t, "ssh-server", cfg.SSH.Upstreams[0].Name)
	assert.Equal(t, "10.0.0.1:22", cfg.SSH.Upstreams[0].Address)

	// Verify SSH config
	assert.Equal(t, "ed25519", cfg.SSH.Gateway.Key.Type)
	assert.Equal(t, 24*time.Hour, cfg.SSH.Gateway.HostCertificate.TTL)
	assert.Equal(t, 5*time.Minute, cfg.SSH.Gateway.UserCertificate.TTL)
	require.NotNil(t, cfg.SSH.CA.Manual)
}

func TestLoad_SSH_Vault(t *testing.T) {
	yaml := `
twingate:
  network: "acme"
tls:
  certificateFile: "tls.crt"
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
      server: "https://vault:8200"
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
  upstreams:
    - name: "ssh-server"
      address: "10.0.0.1:22"
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
  certificateFile: "tls.crt"
  privateKeyFile: "tls.key"
kubernetes:
  upstreams:
    - name: "k8s-cluster"
      inCluster: true
`

	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(tmpFile, []byte(yaml), 0600)
	require.NoError(t, err)

	cfg, err := Load(tmpFile)
	require.NoError(t, err)

	// Check defaults
	assert.Equal(t, 8443, cfg.Port)
	assert.Equal(t, 9090, cfg.MetricsPort)
	assert.Equal(t, time.Minute*10, cfg.AuditLog.FlushInterval)
	assert.Equal(t, 1_000_000, cfg.AuditLog.FlushSizeThreshold)
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
				Twingate:    TwingateConfig{Network: "test"},
				Port:        8443,
				MetricsPort: 9090,
				TLS: TLSConfig{
					CertificateFile: "tls.crt",
					PrivateKeyFile:  "tls.key",
				},
				Kubernetes: &KubernetesConfig{
					Upstreams: []KubernetesUpstream{
						{Name: "k8s", InCluster: true},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing Twingate network",
			config: &Config{
				Port:        8443,
				MetricsPort: 9090,
				TLS: TLSConfig{
					CertificateFile: "tls.crt",
					PrivateKeyFile:  "tls.key",
				},
				Kubernetes: &KubernetesConfig{
					Upstreams: []KubernetesUpstream{
						{Name: "k8s", InCluster: true},
					},
				},
			},
			wantErr:     true,
			errContains: "twingate.network",
		},
		{
			name: "invalid port",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test"},
				Port:        -1,
				MetricsPort: 9090,
				TLS: TLSConfig{
					CertificateFile: "tls.crt",
					PrivateKeyFile:  "tls.key",
				},
				Kubernetes: &KubernetesConfig{
					Upstreams: []KubernetesUpstream{
						{Name: "k8s", InCluster: true},
					},
				},
			},
			wantErr:     true,
			errContains: "port must be between",
		},
		{
			name: "invalid metrics port",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test"},
				Port:        8443,
				MetricsPort: 70000,
				TLS: TLSConfig{
					CertificateFile: "tls.crt",
					PrivateKeyFile:  "tls.key",
				},
				Kubernetes: &KubernetesConfig{
					Upstreams: []KubernetesUpstream{
						{Name: "k8s", InCluster: true},
					},
				},
			},
			wantErr:     true,
			errContains: "metricsPort must be between",
		},
		{
			name: "no protocols configured",
			config: &Config{
				Twingate:    TwingateConfig{Network: "test"},
				Port:        8443,
				MetricsPort: 9090,
				TLS: TLSConfig{
					CertificateFile: "tls.crt",
					PrivateKeyFile:  "tls.key",
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

func TestTLSConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		tls         TLSConfig
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid",
			tls:     TLSConfig{CertificateFile: "tls.crt", PrivateKeyFile: "tls.key"},
			wantErr: false,
		},
		{
			name:        "missing certificate",
			tls:         TLSConfig{PrivateKeyFile: "tls.key"},
			wantErr:     true,
			errContains: "certificateFile",
		},
		{
			name:        "missing private key",
			tls:         TLSConfig{CertificateFile: "tls.crt"},
			wantErr:     true,
			errContains: "privateKeyFile",
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

func TestKubernetesConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		k8s         KubernetesConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid",
			k8s: KubernetesConfig{
				Upstreams: []KubernetesUpstream{
					{Name: "k8s", InCluster: true},
				},
			},
			wantErr: false,
		},
		{
			name: "no upstreams",
			k8s: KubernetesConfig{
				Upstreams: []KubernetesUpstream{},
			},
			wantErr:     true,
			errContains: "at least one upstream is required",
		},
		{
			name: "duplicate upstream names",
			k8s: KubernetesConfig{
				Upstreams: []KubernetesUpstream{
					{Name: "prod-k8s", InCluster: true},
					{Name: "prod-k8s", InCluster: true},
				},
			},
			wantErr:     true,
			errContains: "\"prod-k8s\"",
		},
		{
			name: "multiple in-cluster upstreams",
			k8s: KubernetesConfig{
				Upstreams: []KubernetesUpstream{
					{Name: "cluster-a", InCluster: true},
					{Name: "cluster-b", InCluster: true},
				},
			},
			wantErr:     true,
			errContains: "only one in-cluster upstream is allowed: \"cluster-b\"",
		},
		{
			name: "mixed in-cluster and external cluster",
			k8s: KubernetesConfig{
				Upstreams: []KubernetesUpstream{
					{Name: "local", InCluster: true},
					{Name: "remote", Address: "10.0.0.1:443", BearerToken: "token"},
				},
			},
			wantErr: false,
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

func TestKubernetesUpstream_Validate(t *testing.T) {
	tests := []struct {
		name        string
		upstream    KubernetesUpstream
		wantErr     bool
		errContains string
	}{
		{
			name:     "valid in-cluster",
			upstream: KubernetesUpstream{Name: "k8s", InCluster: true},
			wantErr:  false,
		},
		{
			name: "valid external with token",
			upstream: KubernetesUpstream{
				Name:        "k8s",
				Address:     "10.0.0.1:443",
				BearerToken: "token",
			},
			wantErr: false,
		},
		{
			name: "valid external with token file",
			upstream: KubernetesUpstream{
				Name:            "k8s",
				Address:         "10.0.0.1:443",
				BearerTokenFile: "/path/to/token",
			},
			wantErr: false,
		},
		{
			name:        "missing name",
			upstream:    KubernetesUpstream{InCluster: true},
			wantErr:     true,
			errContains: "name",
		},
		{
			name:        "external missing address",
			upstream:    KubernetesUpstream{Name: "k8s", InCluster: false, BearerToken: "token"},
			wantErr:     true,
			errContains: "address is required",
		},
		{
			name:        "external missing auth",
			upstream:    KubernetesUpstream{Name: "k8s", InCluster: false, Address: "10.0.0.1:443"},
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
			name: "valid with auto-generated CA",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username: "gateway",
					Key: SSHKeyConfig{
						Type: "rsa",
						Bits: 2048,
					},
				},
				CA: SSHCAConfig{},
				Upstreams: []SSHUpstream{
					{Name: "prod", Address: "10.0.0.1:22"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid with manual CA",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username:        "gateway",
					Key:             SSHKeyConfig{Type: "ed25519"},
					HostCertificate: SSHCertificateConfig{TTL: 24 * time.Hour},
					UserCertificate: SSHCertificateConfig{TTL: 5 * time.Minute},
				},
				CA: SSHCAConfig{
					Manual: &SSHCAManualConfig{
						PrivateKeyFile: "ca.key",
					},
				},
				Upstreams: []SSHUpstream{
					{Name: "prod", Address: "10.0.0.1:22"},
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
				Upstreams: []SSHUpstream{
					{Name: "prod", Address: "10.0.0.1:22"},
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
				Upstreams: []SSHUpstream{
					{Name: "prod", Address: "10.0.0.1:22"},
				},
			},
			wantErr:     true,
			errContains: "invalid SSH key type",
		},
		{
			name: "conflicting CA config - both manual and Vault",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username: "gateway",
					Key:      SSHKeyConfig{Type: "ed25519"},
				},
				CA: SSHCAConfig{
					Manual: &SSHCAManualConfig{
						PrivateKeyFile: "ca.key",
					},
					Vault: &SSHCAVaultConfig{
						Address: "https://vault:8200",
						Role:    "gateway",
					},
				},
				Upstreams: []SSHUpstream{
					{Name: "prod", Address: "10.0.0.1:22"},
				},
			},
			wantErr:     true,
			errContains: "only one of 'manual' or 'vault'",
		},
		{
			name: "manual CA missing private key file",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username: "gateway",
				},
				CA: SSHCAConfig{
					Manual: &SSHCAManualConfig{},
				},
				Upstreams: []SSHUpstream{
					{Name: "prod", Address: "10.0.0.1:22"},
				},
			},
			wantErr:     true,
			errContains: "privateKeyFile",
		},
		{
			name: "Vault CA missing server",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username: "gateway",
				},
				CA: SSHCAConfig{
					Vault: &SSHCAVaultConfig{
						Role: "gateway",
					},
				},
				Upstreams: []SSHUpstream{
					{Name: "prod", Address: "10.0.0.1:22"},
				},
			},
			wantErr:     true,
			errContains: "server",
		},
		{
			name: "no upstreams",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username: "gateway",
				},
				CA:        SSHCAConfig{},
				Upstreams: []SSHUpstream{},
			},
			wantErr:     true,
			errContains: "at least one upstream is required",
		},
		{
			name: "duplicate upstream names",
			ssh: SSHConfig{
				Gateway: SSHGatewayConfig{
					Username: "gateway",
				},
				CA: SSHCAConfig{},
				Upstreams: []SSHUpstream{
					{Name: "prod-ssh", Address: "10.0.0.1:22"},
					{Name: "prod-ssh", Address: "10.0.0.2:22"},
				},
			},
			wantErr:     true,
			errContains: "\"prod-ssh\"",
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

func TestSSHUpstream_Validate(t *testing.T) {
	tests := []struct {
		name        string
		upstream    SSHUpstream
		wantErr     bool
		errContains string
	}{
		{
			name:     "valid",
			upstream: SSHUpstream{Name: "ssh", Address: "10.0.0.1:22"},
			wantErr:  false,
		},
		{
			name:        "missing name",
			upstream:    SSHUpstream{Address: "10.0.0.1:22"},
			wantErr:     true,
			errContains: "name",
		},
		{
			name:        "missing address",
			upstream:    SSHUpstream{Name: "ssh"},
			wantErr:     true,
			errContains: "address",
		},
		{
			name:        "invalid address format",
			upstream:    SSHUpstream{Name: "ssh", Address: "invalid"},
			wantErr:     true,
			errContains: "address",
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
	t.Run("missing server", func(t *testing.T) {
		cfg := &SSHCAVaultConfig{Role: "gateway"}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "server")
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

func TestSSHCAVaultAuthConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         SSHCAVaultAuthConfig
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid token",
			cfg:     SSHCAVaultAuthConfig{Token: "token"},
			wantErr: false,
		},
		{
			name: "valid appRole",
			cfg: SSHCAVaultAuthConfig{
				AppRole: &SSHCAVaultAppRoleConfig{
					RoleID:       "role-id",
					SecretIDFile: "/path/to/secret-id",
				},
			},
			wantErr: false,
		},
		{
			name: "valid GCP",
			cfg: SSHCAVaultAuthConfig{
				GCP: &SSHCAVaultGCPConfig{
					Role: "my-role",
					Type: "gce",
				},
			},
			wantErr: false,
		},
		{
			name: "valid AWS",
			cfg: SSHCAVaultAuthConfig{
				AWS: &SSHCAVaultAWSConfig{
					Role: "my-role",
					Type: "iam",
				},
			},
			wantErr: false,
		},
		{
			name:    "valid with empty token (uses VAULT_TOKEN env)",
			cfg:     SSHCAVaultAuthConfig{},
			wantErr: false,
		},
		{
			name: "conflicting config - both token and appRole",
			cfg: SSHCAVaultAuthConfig{
				Token: "token",
				AppRole: &SSHCAVaultAppRoleConfig{
					RoleID:       "role-id",
					SecretIDFile: "/path/to/secret-id",
				},
			},
			wantErr:     true,
			errContains: "only one of 'token', 'appRole', 'gcp', or 'aws'",
		},
		{
			name: "conflicting config - both token and gcp",
			cfg: SSHCAVaultAuthConfig{
				Token: "token",
				GCP: &SSHCAVaultGCPConfig{
					Role: "my-role",
					Type: "gce",
				},
			},
			wantErr:     true,
			errContains: "only one of 'token', 'appRole', 'gcp', or 'aws'",
		},
		{
			name: "conflicting config - both aws and gcp",
			cfg: SSHCAVaultAuthConfig{
				AWS: &SSHCAVaultAWSConfig{
					Role: "my-role",
					Type: "iam",
				},
				GCP: &SSHCAVaultGCPConfig{
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

func TestSSHCAVaultAppRoleConfig_GetMount(t *testing.T) {
	t.Run("default mount", func(t *testing.T) {
		cfg := &SSHCAVaultAppRoleConfig{
			RoleID:       "role-id",
			SecretIDFile: "/path/to/secret-id",
		}
		assert.Equal(t, "approle", cfg.GetMount())
	})

	t.Run("custom mount", func(t *testing.T) {
		cfg := &SSHCAVaultAppRoleConfig{
			Mount:        "custom-approle",
			RoleID:       "role-id",
			SecretIDFile: "/path/to/secret-id",
		}
		assert.Equal(t, "custom-approle", cfg.GetMount())
	})
}

func TestSSHCAVaultAppRoleConfig_Validate(t *testing.T) {
	t.Run("missing roleId", func(t *testing.T) {
		cfg := &SSHCAVaultAppRoleConfig{
			SecretIDFile: "/path/to/secret-id",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "roleID")
	})

	t.Run("missing both secretID and secretIDFile", func(t *testing.T) {
		cfg := &SSHCAVaultAppRoleConfig{
			RoleID: "role-id",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "either secretID or secretIDFile is required")
	})

	t.Run("valid with secretID", func(t *testing.T) {
		cfg := &SSHCAVaultAppRoleConfig{
			RoleID:   "role-id",
			SecretID: "my-secret-id",
		}
		require.NoError(t, cfg.Validate())
	})

	t.Run("valid with secretIDFile", func(t *testing.T) {
		cfg := &SSHCAVaultAppRoleConfig{
			RoleID:       "role-id",
			SecretIDFile: "/path/to/secret-id",
		}
		require.NoError(t, cfg.Validate())
	})

	t.Run("conflicting secretID and secretIDFile", func(t *testing.T) {
		cfg := &SSHCAVaultAppRoleConfig{
			RoleID:       "role-id",
			SecretID:     "my-secret-id",
			SecretIDFile: "/path/to/secret-id",
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, ErrConflictingSecretIDConfig)
	})
}

func TestSSHCAVaultGCPConfig_GetMount(t *testing.T) {
	t.Run("default mount", func(t *testing.T) {
		cfg := &SSHCAVaultGCPConfig{
			Role: "my-role",
			Type: "gce",
		}
		assert.Equal(t, "gcp", cfg.GetMount())
	})

	t.Run("custom mount", func(t *testing.T) {
		cfg := &SSHCAVaultGCPConfig{
			Mount: "custom-gcp",
			Role:  "my-role",
			Type:  "gce",
		}
		assert.Equal(t, "custom-gcp", cfg.GetMount())
	})
}

func TestSSHCAVaultGCPConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *SSHCAVaultGCPConfig
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid GCE",
			cfg:     &SSHCAVaultGCPConfig{Role: "my-role", Type: "gce"},
			wantErr: false,
		},
		{
			name:    "valid IAM",
			cfg:     &SSHCAVaultGCPConfig{Role: "my-role", Type: "iam", ServiceAccountEmail: "gateway-sa@project.iam.gserviceaccount.com"},
			wantErr: false,
		},
		{
			name:    "valid GCE type case insensitive",
			cfg:     &SSHCAVaultGCPConfig{Role: "my-role", Type: "GCE"},
			wantErr: false,
		},
		{
			name:        "missing role",
			cfg:         &SSHCAVaultGCPConfig{Type: "gce"},
			wantErr:     true,
			errContains: "role",
		},
		{
			name:        "missing type",
			cfg:         &SSHCAVaultGCPConfig{Role: "my-role"},
			wantErr:     true,
			errContains: "type",
		},
		{
			name:        "invalid type",
			cfg:         &SSHCAVaultGCPConfig{Role: "my-role", Type: "invalid"},
			wantErr:     true,
			errContains: "gcp type must be 'gce' or 'iam'",
		},
		{
			name:        "IAM type missing serviceAccountEmail",
			cfg:         &SSHCAVaultGCPConfig{Role: "my-role", Type: "iam"},
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

func TestSSHCAVaultAWSConfig_GetMount(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *SSHCAVaultAWSConfig
		expected string
	}{
		{
			name: "default mount",
			cfg: &SSHCAVaultAWSConfig{
				Role: "my-role",
				Type: "iam",
			},
			expected: "aws",
		},
		{
			name: "custom mount",
			cfg: &SSHCAVaultAWSConfig{
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

func TestSSHCAVaultAWSConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *SSHCAVaultAWSConfig
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid IAM",
			cfg:     &SSHCAVaultAWSConfig{Role: "my-role", Type: "iam"},
			wantErr: false,
		},
		{
			name:    "valid EC2",
			cfg:     &SSHCAVaultAWSConfig{Role: "my-role", Type: "ec2"},
			wantErr: false,
		},
		{
			name:    "valid EC2 with signatureType and nonce",
			cfg:     &SSHCAVaultAWSConfig{Role: "my-role", Type: "ec2", SignatureType: "identity", Nonce: "my-nonce"},
			wantErr: false,
		},
		{
			name:    "Valid IAM case insensitive type",
			cfg:     &SSHCAVaultAWSConfig{Role: "my-role", Type: "IAM"},
			wantErr: false,
		},
		{
			name:        "missing role",
			cfg:         &SSHCAVaultAWSConfig{Type: "iam"},
			wantErr:     true,
			errContains: "role",
		},
		{
			name:        "missing type",
			cfg:         &SSHCAVaultAWSConfig{Role: "my-role"},
			wantErr:     true,
			errContains: "type",
		},
		{
			name:        "invalid type",
			cfg:         &SSHCAVaultAWSConfig{Role: "my-role", Type: "invalid"},
			wantErr:     true,
			errContains: "aws type must be 'iam' or 'ec2'",
		},
		{
			name:        "invalid signatureType",
			cfg:         &SSHCAVaultAWSConfig{Role: "my-role", Type: "ec2", SignatureType: "invalid"},
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

func TestValidateAddress(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid IPv4 with port",
			address: "192.168.1.1:22",
			wantErr: false,
		},
		{
			name:    "valid hostname with port",
			address: "example.com:443",
			wantErr: false,
		},
		{
			name:    "valid IPv6 with port",
			address: "[2001:db8::1]:8080",
			wantErr: false,
		},
		{
			name:    "valid localhost with port",
			address: "localhost:3000",
			wantErr: false,
		},
		{
			name:        "missing port",
			address:     "192.168.1.1",
			wantErr:     true,
			errContains: "missing port in address",
		},
		{
			name:        "missing host",
			address:     ":8080",
			wantErr:     true,
			errContains: "host cannot be empty",
		},
		{
			name:        "empty port",
			address:     "example.com:",
			wantErr:     true,
			errContains: "port cannot be empty",
		},
		{
			name:        "empty string",
			address:     "",
			wantErr:     true,
			errContains: "missing port in address",
		},
		{
			name:        "only colon",
			address:     ":",
			wantErr:     true,
			errContains: "host cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAddress(tt.address)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.ErrorIs(t, err, ErrInvalidAddress)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
