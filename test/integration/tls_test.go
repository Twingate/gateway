// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/proxy"
	"gateway/test/fake"
	"gateway/test/integration/testutil"
)

// TestTLSVault tests downstream TLS certificates minted through Vault's PKI
// secrets engine: the Gateway completes a handshake with a certificate that
// chains to the Vault CA and covers the dialed host.
func TestTLSVault(t *testing.T) {
	const gatewayPort = 8452

	vaultContainerID, vaultPort := testutil.SetupVaultServer(t)
	vaultAddress := fmt.Sprintf("http://127.0.0.1:%d", vaultPort)

	rootCAs := vaultPKIRootPool(t, vaultAddress)

	tests := []struct {
		name      string
		authSetup func(t *testing.T) gatewayconfig.VaultAuthConfig
	}{
		{
			name: "token",
			authSetup: func(t *testing.T) gatewayconfig.VaultAuthConfig {
				t.Helper()

				return gatewayconfig.VaultAuthConfig{
					Token: testutil.SetupVaultToken(t, vaultContainerID),
				}
			},
		},
		{
			name: "approle",
			authSetup: func(t *testing.T) gatewayconfig.VaultAuthConfig {
				t.Helper()

				roleID, secretID := testutil.SetupVaultAppRole(t, vaultContainerID)

				return gatewayconfig.VaultAuthConfig{
					AppRole: &gatewayconfig.VaultAppRoleConfig{
						RoleID:   roleID,
						SecretID: secretID,
					},
				}
			},
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := gatewayPort + i

			controller := fake.NewController(network, 8080)
			t.Cleanup(controller.Close)

			config := gatewayconfig.Config{
				Twingate: gatewayconfig.TwingateConfig{
					Network: network,
					Host:    host,
				},
				Port:        port,
				MetricsPort: 0,
				TLS: gatewayconfig.TLSConfig{
					Automation: &gatewayconfig.TLSAutomationConfig{
						Issuer: gatewayconfig.TLSIssuerConfig{
							Vault: &gatewayconfig.TLSVaultIssuerConfig{
								Address: vaultAddress,
								Auth:    tt.authSetup(t),
								Role:    "gateway-tls",
							},
						},
					},
				},
				WebApp: &gatewayconfig.WebAppConfig{},
			}

			p, err := proxy.NewProxy(&config, prometheus.NewRegistry(), zap.NewNop())
			require.NoError(t, err, "failed to create proxy")

			go func() {
				err := p.Start()
				t.Logf("Failed to start Gateway: %v", err)
			}()

			// The health check dials by IP without SNI, so readiness already
			// proves the local-address fallback mints an IP certificate via Vault.
			testutil.GatewayHealthCheck(t, port)

			conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
				ServerName: "app.acme.int",
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS13,
			})
			require.NoError(t, err, "handshake should verify against the Vault CA")

			t.Cleanup(func() { _ = conn.Close() })

			leaf := conn.ConnectionState().PeerCertificates[0]
			assert.Equal(t, []string{"app.acme.int"}, leaf.DNSNames)
			assert.Equal(t, "app.acme.int", leaf.Subject.CommonName)
		})
	}
}

// vaultPKIRootPool fetches the PKI mount's root CA for client-side verification.
func vaultPKIRootPool(t *testing.T, vaultAddress string) *x509.CertPool {
	t.Helper()

	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(vaultAddress + "/v1/pki/ca/pem")
	require.NoError(t, err, "failed to fetch the Vault PKI root CA")

	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	caPEM, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM), "failed to parse the Vault PKI root CA")

	return pool
}
