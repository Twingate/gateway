// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/ssh"

	vault "github.com/hashicorp/vault/api"

	gatewayconfig "gateway/internal/config"
	"gateway/test/data"
)

func TestEmbeddedCA_PublicKey(t *testing.T) {
	signer, pubKey, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	ca := &embeddedCA{
		getSigner: staticSigner(signer),
	}

	got, err := ca.publicKey(context.Background())
	require.NoError(t, err)
	require.Equal(t, pubKey.Marshal(), got.Marshal())
}

func TestEmbeddedCA_Sign(t *testing.T) {
	caSigner, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	ca := &embeddedCA{
		getSigner: staticSigner(caSigner),
	}

	publicKey, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	tests := []struct {
		name     string
		certType certType
	}{
		{name: "host cert", certType: HostCert},
		{name: "user cert", certType: UserCert},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &certificateRequest{
				certType:   tt.certType,
				publicKey:  publicKey,
				principals: []string{"test-principal"},
				ttl:        1 * time.Hour,
				permissions: ssh.Permissions{
					Extensions: map[string]string{"permit-pty": ""},
				},
			}

			cert, err := ca.sign(context.Background(), req)
			require.NoError(t, err)

			require.Equal(t, uint32(tt.certType), cert.CertType)
			require.Equal(t, publicKey.Marshal(), cert.Key.Marshal())
			require.Equal(t, []string{"test-principal"}, cert.ValidPrincipals)
			require.Equal(t, "twingate-14190c5d6ad4cbfa2e58069d25e06435f54c880654becf86735e9a77f49dc92b", cert.KeyId)
			require.Equal(t, map[string]string{"permit-pty": ""}, cert.Extensions)

			now := time.Now()
			require.LessOrEqual(t, cert.ValidAfter, mustUint64(now))
			require.Greater(t, cert.ValidBefore, mustUint64(now))
		})
	}
}

func TestNewManualCA_Success(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	caConfig, err := newManualCA("../../test/data/ssh/ca/ca", logger)
	require.NoError(t, err)

	require.NotNil(t, caConfig.GatewayHostCA)
	require.NotNil(t, caConfig.GatewayUserCA)
	require.Nil(t, caConfig.UpstreamHostCA, "UpstreamHostCA should be nil for TOFU mode")
	require.NotNil(t, caConfig.keyReloader, "keyReloader should watch the manual CA key file")

	require.Same(t, caConfig.GatewayHostCA, caConfig.GatewayUserCA, "GatewayHostCA and GatewayUserCA should be the same instance")

	expectedPubKey, err := parsePublicKey(data.SSHCAPublicKey)
	require.NoError(t, err)

	pubKey, err := caConfig.GatewayHostCA.publicKey(context.Background())
	require.NoError(t, err)
	require.Equal(t, expectedPubKey.Marshal(), pubKey.Marshal())

	allLogs := logs.All()
	require.Len(t, allLogs, 1, "Expected exactly one log message")

	log := allLogs[0]
	require.Equal(t, "Using manual CA for SSH authentication", log.Message)
	require.Equal(t, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey))), log.ContextMap()["ca_public_key"])
}

func TestNewManualCA_PrivateKeyFileNotFound(t *testing.T) {
	_, err := newManualCA("/nonexistent/ca", zap.NewNop())
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read private key file")
}

func TestNewCAFromConfig_EmptyConfig(t *testing.T) {
	_, err := newCAFromConfig(gatewayconfig.SSHCAConfig{}, zap.NewNop())
	require.ErrorIs(t, err, gatewayconfig.ErrMissingCAConfig)
}

func TestNewCAFromConfig_ManualConfig(t *testing.T) {
	config := gatewayconfig.SSHCAConfig{
		Manual: &gatewayconfig.SSHCAManualConfig{
			PrivateKeyFile: "../../test/data/ssh/ca/ca",
		},
	}

	caConfig, err := newCAFromConfig(config, zap.NewNop())
	require.NoError(t, err)

	require.IsType(t, &embeddedCA{}, caConfig.GatewayHostCA)
	require.IsType(t, &embeddedCA{}, caConfig.GatewayUserCA)
	require.Nil(t, caConfig.UpstreamHostCA)
}

func TestUpstreamHostKeyCallback_NilUpstreamHostCA(t *testing.T) {
	upstreamAddress := "10.0.0.1:22"
	caConfig := &caConfig{
		UpstreamHostCA: nil,
	}

	callback, err := caConfig.upstreamHostKeyCallback(context.Background(), upstreamAddress)
	require.NoError(t, err)
	require.NotNil(t, callback)

	publicKey, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	// TOFU verification with public key
	err = callback(upstreamAddress, nil, publicKey)
	require.NoError(t, err)
}

func TestUpstreamHostKeyCallback_WithUpstreamHostCA(t *testing.T) {
	upstreamAddress := "10.0.0.1:22"
	caSigner, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	upstreamCA := &embeddedCA{
		getSigner: staticSigner(caSigner),
	}

	caConfig := &caConfig{
		UpstreamHostCA: upstreamCA,
	}

	callback, err := caConfig.upstreamHostKeyCallback(context.Background(), upstreamAddress)
	require.NoError(t, err)
	require.NotNil(t, callback)

	hostSigner, hostPubKey, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	req := &certificateRequest{
		certType:  HostCert,
		publicKey: hostPubKey,
		ttl:       1 * time.Hour,
	}

	cert, err := upstreamCA.sign(context.Background(), req)
	require.NoError(t, err)

	certSigner, err := ssh.NewCertSigner(cert, hostSigner)
	require.NoError(t, err)

	err = callback(upstreamAddress, nil, certSigner.PublicKey())
	require.NoError(t, err)
}

func TestUpstreamHostKeyCallback_WithUpstreamHostCA_RejectsPublicKey(t *testing.T) {
	upstreamAddress := "10.0.0.1:22"
	caSigner, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	upstreamCA := &embeddedCA{
		getSigner: staticSigner(caSigner),
	}

	caConfig := &caConfig{
		UpstreamHostCA: upstreamCA,
	}

	callback, err := caConfig.upstreamHostKeyCallback(context.Background(), upstreamAddress)
	require.NoError(t, err)

	pubKey, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	err = callback(upstreamAddress, nil, pubKey)
	require.Error(t, err)
}

func TestMustUint64(t *testing.T) {
	tests := []struct {
		name   string
		input  time.Time
		expect uint64
	}{
		{name: "current time", input: time.Unix(1234567890, 0), expect: 1234567890},
		{name: "epoch", input: time.Unix(0, 0), expect: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mustUint64(tt.input)
			require.Equal(t, tt.expect, result)
		})
	}
}

func TestMustUint64_PanicsOnNegativeTime(t *testing.T) {
	require.Panics(t, func() {
		mustUint64(time.Unix(-1, 0))
	})
}

// staticSigner returns a signer getter for a CA whose key never changes.
func staticSigner(signer ssh.Signer) func() ssh.Signer {
	return func() ssh.Signer {
		return signer
	}
}

// newVaultTestCA returns a vaultCA whose client talks to a test server running handler.
func newVaultTestCA(t *testing.T, handler http.HandlerFunc) *vaultCA {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	config := vault.DefaultConfig()
	config.Address = server.URL
	config.MaxRetries = 0 // Fail fast on error responses instead of retrying with backoff.

	client, err := vault.NewClient(config)
	require.NoError(t, err)
	client.SetToken("test-token")

	return &vaultCA{client: client, mount: "ssh", role: "test-role"}
}

func TestVaultCA_PublicKey(t *testing.T) {
	caPublicKey, err := parsePublicKey(data.SSHCAPublicKey)
	require.NoError(t, err)

	tests := []struct {
		name         string
		responseData map[string]any // nil sends {"data": null}
		wantErr      error
		wantKey      bool
	}{
		{name: "success", responseData: map[string]any{"public_key": string(data.SSHCAPublicKey)}, wantKey: true},
		{name: "null data", responseData: nil, wantErr: errVaultCAFailed},
		{name: "missing public key", responseData: map[string]any{}, wantErr: errVaultCAFailed},
		{name: "empty public key", responseData: map[string]any{"public_key": ""}, wantErr: errVaultCAFailed},
		{name: "unparseable public key", responseData: map[string]any{"public_key": "not-a-key"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newVaultTestCA(t, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": tt.responseData})
			})

			publicKey, err := ca.publicKey(t.Context())

			if tt.wantKey {
				require.NoError(t, err)
				assert.True(t, keysEqual(publicKey, caPublicKey))

				return
			}

			require.Error(t, err)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestVaultCA_PublicKey_RequestFails(t *testing.T) {
	ca := newVaultTestCA(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := ca.publicKey(t.Context())
	require.Error(t, err)
	require.NotErrorIs(t, err, errVaultCAFailed)
}

func TestVaultCA_Sign(t *testing.T) {
	publicKey, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	// CA the test server signs with; the gateway never verifies it against this key.
	caSigner, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name           string
		req            *certificateRequest
		wantCertType   string
		wantPrincipals string
		wantExtensions map[string]string // nil means the field must be absent from the request
	}{
		{
			name: "user cert",
			req: &certificateRequest{
				certType:   UserCert,
				publicKey:  publicKey,
				principals: []string{"alice", "bob"},
				ttl:        time.Hour,
				permissions: ssh.Permissions{
					Extensions: map[string]string{"permit-pty": ""},
				},
			},
			wantCertType:   "user",
			wantPrincipals: "alice,bob",
			wantExtensions: map[string]string{"permit-pty": ""},
		},
		{
			name: "host cert",
			req: &certificateRequest{
				certType:   HostCert,
				publicKey:  publicKey,
				principals: []string{"gateway.example.com"},
				ttl:        24 * time.Hour,
			},
			wantCertType:   "host",
			wantPrincipals: "gateway.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newVaultTestCA(t, func(w http.ResponseWriter, r *http.Request) {
				var gotData map[string]any
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&gotData))

				// The server checks the request payload the gateway built for the request.
				assert.Equal(t, tt.wantCertType, gotData["cert_type"])
				assert.Equal(t, string(ssh.MarshalAuthorizedKey(publicKey)), gotData["public_key"])
				assert.Equal(t, tt.wantPrincipals, gotData["valid_principals"])
				assert.Equal(t, tt.req.ttl.String(), gotData["ttl"])

				if tt.wantExtensions == nil {
					assert.NotContains(t, gotData, "extensions", "extensions must not be sent for host certs")
				} else if ext, ok := gotData["extensions"].(map[string]any); assert.True(t, ok) {
					assert.Len(t, ext, len(tt.wantExtensions))

					for k := range tt.wantExtensions {
						assert.Contains(t, ext, k, "missing extension %q", k)
					}
				}

				cert := &ssh.Certificate{
					Key:             publicKey,
					CertType:        uint32(tt.req.certType),
					ValidPrincipals: tt.req.principals,
					ValidBefore:     mustUint64(time.Now().Add(tt.req.ttl)),
					Permissions:     tt.req.permissions,
				}
				assert.NoError(t, cert.SignCert(rand.Reader, caSigner))

				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{"signed_key": string(ssh.MarshalAuthorizedKey(cert))},
				})
			})

			cert, err := ca.sign(t.Context(), tt.req)
			require.NoError(t, err)
			assert.NotNil(t, cert)
		})
	}
}

func TestVaultCA_Sign_Error(t *testing.T) {
	publicKey, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	req := &certificateRequest{
		certType:   UserCert,
		publicKey:  publicKey,
		principals: []string{"alice"},
		ttl:        time.Hour,
		permissions: ssh.Permissions{
			Extensions: map[string]string{"permit-pty": ""},
		},
	}

	// A syntactically valid cert that grants an extra principal, to exercise the verifyCertificate path.
	caSigner, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	overBroadCert := &ssh.Certificate{
		Key:             publicKey,
		CertType:        uint32(UserCert),
		ValidPrincipals: []string{"alice", "root"},
		ValidBefore:     mustUint64(time.Now().Add(30 * time.Minute)),
	}
	require.NoError(t, overBroadCert.SignCert(rand.Reader, caSigner))

	tests := []struct {
		name         string
		responseData map[string]any
		wantErr      error
	}{
		{name: "missing signed key", responseData: map[string]any{}, wantErr: errVaultSignFailed},
		{name: "empty signed key", responseData: map[string]any{"signed_key": ""}, wantErr: errVaultSignFailed},
		{name: "unparseable signed key", responseData: map[string]any{"signed_key": "not-a-certificate"}},
		{name: "certificate violates policy", responseData: map[string]any{"signed_key": string(ssh.MarshalAuthorizedKey(overBroadCert))}, wantErr: errCertPolicyViolation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newVaultTestCA(t, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": tt.responseData})
			})

			_, err := ca.sign(t.Context(), req)
			require.Error(t, err)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestVaultCA_Sign_RequestFails(t *testing.T) {
	publicKey, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	req := &certificateRequest{
		certType:   UserCert,
		publicKey:  publicKey,
		principals: []string{"alice"},
		ttl:        time.Hour,
		permissions: ssh.Permissions{
			Extensions: map[string]string{"permit-pty": ""},
		},
	}

	ca := newVaultTestCA(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err = ca.sign(t.Context(), req)
	require.Error(t, err)
	require.NotErrorIs(t, err, errVaultSignFailed)
}

func TestVerifyCertificate(t *testing.T) {
	publicKey, err := parsePublicKey(data.SSHHostPublicKey)
	require.NoError(t, err)

	otherPublicKey, err := parsePublicKey(data.SSHCAPublicKey)
	require.NoError(t, err)

	now := time.Now()

	tests := []struct {
		name       string
		setupFn    func(req *certificateRequest, cert *ssh.Certificate)
		wantErrMsg string // substring expected in the error; empty means no error
	}{
		{
			name:    "valid user cert",
			setupFn: func(*certificateRequest, *ssh.Certificate) {},
		},
		{
			name: "valid host cert",
			setupFn: func(req *certificateRequest, cert *ssh.Certificate) {
				req.certType = HostCert
				req.principals = nil
				req.permissions.Extensions = nil
				cert.CertType = uint32(HostCert)
				cert.ValidPrincipals = nil
				cert.Extensions = nil
			},
		},
		{
			name: "wrong cert type",
			setupFn: func(_ *certificateRequest, cert *ssh.Certificate) {
				cert.CertType = uint32(HostCert)
			},
			wantErrMsg: "cert type",
		},
		{
			name: "wrong public key",
			setupFn: func(_ *certificateRequest, cert *ssh.Certificate) {
				cert.Key = otherPublicKey
			},
			wantErrMsg: "different public key",
		},
		{
			name: "extra principal",
			setupFn: func(_ *certificateRequest, cert *ssh.Certificate) {
				cert.ValidPrincipals = []string{"alice", "root"}
			},
			wantErrMsg: "do not match requested",
		},
		{
			name: "empty principals is wildcard",
			setupFn: func(_ *certificateRequest, cert *ssh.Certificate) {
				cert.ValidPrincipals = nil
			},
			wantErrMsg: "do not match requested",
		},
		{
			name: "empty principals matches empty request",
			setupFn: func(req *certificateRequest, cert *ssh.Certificate) {
				req.principals = nil
				cert.ValidPrincipals = nil
			},
		},
		{
			name: "validity exceeds TTL",
			setupFn: func(_ *certificateRequest, cert *ssh.Certificate) {
				cert.ValidBefore = mustUint64(now.Add(2 * time.Hour))
			},
			wantErrMsg: "exceeds requested TTL",
		},
		{
			name: "no expiry",
			setupFn: func(_ *certificateRequest, cert *ssh.Certificate) {
				cert.ValidBefore = ssh.CertTimeInfinity
			},
			wantErrMsg: "exceeds requested TTL",
		},
		{
			name: "unrequested critical option",
			setupFn: func(_ *certificateRequest, cert *ssh.Certificate) {
				cert.CriticalOptions = map[string]string{"force-command": "/bin/false"}
			},
			wantErrMsg: "critical options",
		},
		{
			name: "critical option value mismatch",
			setupFn: func(req *certificateRequest, cert *ssh.Certificate) {
				req.permissions.CriticalOptions = map[string]string{"force-command": "/usr/bin/allowed"}
				cert.CriticalOptions = map[string]string{"force-command": "/bin/sh"}
			},
			wantErrMsg: "critical options",
		},
		{
			name: "missing requested critical option",
			setupFn: func(req *certificateRequest, _ *ssh.Certificate) {
				req.permissions.CriticalOptions = map[string]string{"force-command": "/usr/bin/allowed"}
			},
			wantErrMsg: "critical options",
		},
		{
			name: "unrequested extension",
			setupFn: func(_ *certificateRequest, cert *ssh.Certificate) {
				cert.Extensions["permit-port-forwarding"] = ""
			},
			wantErrMsg: "unexpected extension",
		},
		{
			name: "extension value mismatch",
			setupFn: func(_ *certificateRequest, cert *ssh.Certificate) {
				cert.Extensions["permit-pty"] = "unexpected"
			},
			wantErrMsg: "extension \"permit-pty\" granted value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &certificateRequest{
				certType:   UserCert,
				publicKey:  publicKey,
				principals: []string{"alice"},
				ttl:        time.Hour,
				permissions: ssh.Permissions{
					Extensions: map[string]string{"permit-pty": ""},
				},
			}
			cert := &ssh.Certificate{
				Key:             publicKey,
				CertType:        uint32(UserCert),
				ValidPrincipals: []string{"alice"},
				ValidAfter:      mustUint64(now.Add(-clockSkewBuffer)),
				ValidBefore:     mustUint64(now.Add(30 * time.Minute)),
				Permissions: ssh.Permissions{
					Extensions: map[string]string{"permit-pty": ""},
				},
			}
			tt.setupFn(req, cert)

			err := verifyCertificate(cert, req)
			if tt.wantErrMsg != "" {
				require.ErrorIs(t, err, errCertPolicyViolation)
				assert.ErrorContains(t, err, tt.wantErrMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
