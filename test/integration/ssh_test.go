// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"k8s.io/apimachinery/pkg/util/wait"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/proxy"
	"gateway/internal/token"
	"gateway/test/data"
	"gateway/test/fake"
	"gateway/test/integration/testutil"
)

const sshUsername = "admin"

type sshTestEnv struct {
	containerID string
	user        *testutil.SSHUser
	logs        *observer.ObservedLogs
}

func setupSSHGateway(t *testing.T, user *token.User, sshCAConfig gatewayconfig.SSHCAConfig, gatewayPort int) *sshTestEnv {
	t.Helper()

	containerID, sshServerPort := testutil.SetupSSHServer(t, sshUsername)
	sshServerAddress := fmt.Sprintf("127.0.0.1:%d", sshServerPort)

	controller := fake.NewController(network, 8080)

	t.Cleanup(func() { controller.Close() })

	config := gatewayconfig.Config{
		Twingate: gatewayconfig.TwingateConfig{
			Network: network,
			Host:    host,
		},
		Port:        gatewayPort,
		MetricsPort: 0,
		TLS: gatewayconfig.TLSConfig{
			CertificateFile: "../data/proxy/tls.crt",
			PrivateKeyFile:  "../data/proxy/tls.key",
		},
		SSH: &gatewayconfig.SSHConfig{
			Gateway: gatewayconfig.SSHGatewayConfig{
				Username: sshUsername,
			},
			CA: sshCAConfig,
			Upstreams: []gatewayconfig.SSHUpstream{
				{Name: "ssh-server", Address: sshServerAddress},
			},
		},
	}

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core).Named("test")

	p, err := proxy.NewProxy(&config, prometheus.NewRegistry(), logger)
	require.NoError(t, err, "failed to create proxy")

	go func() {
		err := p.Start()
		t.Logf("Failed to start Gateway: %v", err)
	}()

	testutil.GatewayHealthCheck(t, gatewayPort)

	knownHostsFile := filepath.Join(t.TempDir(), "known_hosts")
	line := "@cert-authority * " + string(data.SSHCAPublicKey)
	require.NoError(t, os.WriteFile(knownHostsFile, []byte(line), 0600))

	sshUser, err := testutil.NewSSHUser(
		user,
		gatewayPort,
		sshServerAddress,
		controller.URL,
		knownHostsFile,
	)
	require.NoError(t, err, "failed to create SSH user")

	t.Cleanup(func() { sshUser.Close() })

	return &sshTestEnv{
		containerID: containerID,
		user:        sshUser,
		logs:        logs,
	}
}

// TestSSH tests the following properties:
// - User can execute commands via SSH through the gateway
// - Session recording (asciicast) is properly generated
// - User can copy file from remote server to host.
func TestSSH(t *testing.T) {
	const gatewayPort = 8445

	env := setupSSHGateway(t, &token.User{
		ID:       "user-ssh-1",
		Username: "alex@acme.com",
		Groups:   []string{"OnCall", "Engineering"},
	}, gatewayconfig.SSHCAConfig{
		Manual: &gatewayconfig.SSHCAManualConfig{
			PrivateKeyFile: "../data/ssh/ca/ca",
		},
	}, gatewayPort)

	// Test `ssh 127.0.0.1 -l admin -p 2222 "whoami"`
	output, err := env.user.SSH.Command("whoami")
	require.NoError(t, err, "failed to execute 'whoami' command")

	assert.Equalf(t, sshUsername+"\n", string(output), "whoami should return '%s'", sshUsername)

	// Wait for logs to be flushed
	time.Sleep(100 * time.Millisecond)

	expectedRequest := map[string]any{
		"type":    "exec",
		"command": "whoami",
		"source":  "downstream",
		"target":  "upstream",
	}
	expectedUser := map[string]any{
		"id":       "user-ssh-1",
		"username": "alex@acme.com",
		"groups":   []any{"OnCall", "Engineering"},
	}
	testutil.AssertLogsForSSH(t, env.logs, expectedUser, expectedRequest)

	// Clear existing logs
	env.logs.TakeAll()

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err = testutil.RunCommand(exec.Command("docker", "exec", env.containerID, "sh", "-c", "echo 'test file copy' > /tmp/test.txt"))
	require.NoError(t, err, "failed to create test file in docker container")

	// Test `scp -P 2222 admin@127.0.0.1:/tmp/test.txt /tmp/dir/test.txt`
	tmpFile := filepath.Join(t.TempDir(), "test.txt")
	_, err = env.user.SSH.CopyFileToHost("/tmp/test.txt", tmpFile)
	require.NoError(t, err, "failed to copy '/tmp/test.txt' file locally")

	// #nosec G304 -- file paths are from trusted operator configuration
	fileContent, err := os.ReadFile(tmpFile)
	require.NoErrorf(t, err, "failed to read file %s", tmpFile)

	require.Equal(t, "test file copy\n", string(fileContent))

	// Wait for logs to be flushed
	time.Sleep(100 * time.Millisecond)

	expectedRequest = map[string]any{
		"type":   "subsystem",
		"name":   "sftp",
		"source": "downstream",
		"target": "upstream",
	}
	testutil.AssertLogsForSSH(t, env.logs, expectedUser, expectedRequest)
}

// TestSSHVault tests SSH proxying through the gateway using Vault as the CA backend.
func TestSSHVault(t *testing.T) {
	const gatewayPort = 8448

	vaultContainerID, vaultPort := testutil.SetupVaultServer(t)
	vaultAddress := fmt.Sprintf("http://127.0.0.1:%d", vaultPort)

	tests := []struct {
		name      string
		authSetup func(t *testing.T) gatewayconfig.SSHCAVaultAuthConfig
	}{
		{
			name: "token",
			authSetup: func(t *testing.T) gatewayconfig.SSHCAVaultAuthConfig {
				t.Helper()

				return gatewayconfig.SSHCAVaultAuthConfig{
					Token: testutil.SetupVaultToken(t, vaultContainerID),
				}
			},
		},
		{
			name: "approle",
			authSetup: func(t *testing.T) gatewayconfig.SSHCAVaultAuthConfig {
				t.Helper()

				roleID, secretID := testutil.SetupVaultAppRole(t, vaultContainerID)

				return gatewayconfig.SSHCAVaultAuthConfig{
					AppRole: &gatewayconfig.SSHCAVaultAppRoleConfig{
						RoleID:   roleID,
						SecretID: secretID,
					},
				}
			},
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := tt.authSetup(t)
			env := setupSSHGateway(t, &token.User{
				ID:       "user-ssh-1",
				Username: "alex@acme.com",
				Groups:   []string{"OnCall", "Engineering"},
			}, gatewayconfig.SSHCAConfig{
				Vault: &gatewayconfig.SSHCAVaultConfig{
					Address: vaultAddress,
					Mount:   "ssh",
					Role:    "gateway-signer",
					Auth:    auth,
				},
			}, gatewayPort+i)

			// Test `ssh 127.0.0.1 -l admin -p 2222 "whoami"`
			output, err := env.user.SSH.Command("whoami")
			require.NoError(t, err, "failed to execute 'whoami' command")

			assert.Equalf(t, sshUsername+"\n", string(output), "whoami should return '%s'", sshUsername)
		})
	}
}

// TestSSHLocalPortForwarding tests that local port forwarding (-L) works through the gateway.
// This exercises the direct-tcpip channel forwarding in conn_pair.go.
func TestSSHLocalPortForwarding(t *testing.T) {
	const (
		gatewayPort    = 8446
		echoServerPort = 8888
		localPort      = 18888
	)

	env := setupSSHGateway(t, &token.User{
		ID:       "user-ssh-local-fwd",
		Username: "alex@acme.com",
		Groups:   []string{"Engineering"},
	}, gatewayconfig.SSHCAConfig{
		Manual: &gatewayconfig.SSHCAManualConfig{
			PrivateKeyFile: "../data/ssh/ca/ca",
		},
	}, gatewayPort)

	testutil.SetupRemoteEchoServer(t, env.containerID, echoServerPort)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	var sshStderr bytes.Buffer

	cmd := env.user.SSH.LocalPortForward(ctx, localPort, "127.0.0.1", echoServerPort)
	cmd.Stderr = &sshStderr

	require.NoError(t, cmd.Start(), "failed to start SSH local port forwarding")

	t.Cleanup(func() {
		cancel()

		_ = cmd.Wait()

		if sshStderr.Len() > 0 {
			t.Logf("SSH local port forward stderr: %s", sshStderr.String())
		}
	})

	// Wait for the tunnel to be established by polling the forwarded port
	var conn net.Conn

	err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 10*time.Second, true, func(_ context.Context) (bool, error) {
		var dialErr error

		conn, dialErr = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), time.Second)
		if dialErr != nil {
			return false, nil //nolint:nilerr
		}

		return true, nil
	})
	require.NoError(t, err, "failed to connect to local forwarded port")

	defer conn.Close()

	// Send data through the tunnel and verify the echo server echoes it back
	testData := "hello local port forwarding\n"

	_, err = conn.Write([]byte(testData))
	require.NoError(t, err, "failed to write to forwarded port")

	require.NoError(t, conn.(*net.TCPConn).CloseWrite())

	response, err := io.ReadAll(conn)
	require.NoError(t, err, "failed to read from forwarded port")

	assert.Equal(t, testData, string(response))

	// Assert audit logs for local port forwarding
	expectedUser := map[string]any{
		"id":       "user-ssh-local-fwd",
		"username": "alex@acme.com",
		"groups":   []any{"Engineering"},
	}
	expectedChannel := map[string]any{
		"type":   "direct-tcpip",
		"source": "downstream",
		"target": "upstream",
	}
	testutil.AssertLogsForSSHChannel(t, env.logs, expectedUser, expectedChannel)
}

// TestSSHRemotePortForwarding tests that remote port forwarding (-R) works through the gateway.
// This exercises the tcpip-forward global request and forwarded-tcpip channel forwarding in conn_pair.go.
func TestSSHRemotePortForwarding(t *testing.T) {
	const (
		gatewayPort   = 8447
		localEchoPort = 19999
		remotePort    = 9999
	)

	env := setupSSHGateway(t, &token.User{
		ID:       "user-ssh-remote-fwd",
		Username: "alex@acme.com",
		Groups:   []string{"Engineering"},
	}, gatewayconfig.SSHCAConfig{
		Manual: &gatewayconfig.SSHCAManualConfig{
			PrivateKeyFile: "../data/ssh/ca/ca",
		},
	}, gatewayPort)

	testutil.SetupLocalEchoServer(t, localEchoPort)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	var sshStderr bytes.Buffer

	cmd := env.user.SSH.RemotePortForward(ctx, remotePort, "127.0.0.1", localEchoPort)
	cmd.Stderr = &sshStderr

	require.NoError(t, cmd.Start(), "failed to start SSH remote port forwarding")

	t.Cleanup(func() {
		cancel()

		_ = cmd.Wait()

		if sshStderr.Len() > 0 {
			t.Logf("SSH remote port forward stderr: %s", sshStderr.String())
		}
	})

	// Wait for the remote tunnel to be established by polling from inside the container
	var output []byte

	err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 10*time.Second, true, func(_ context.Context) (bool, error) {
		var cmdErr error

		output, cmdErr = testutil.RunCommand(exec.Command( // #nosec G204 -- inputs are from trusted operator configuration
			"docker", "exec", env.containerID, "sh", "-c",
			fmt.Sprintf("echo 'hello remote port forwarding' | nc -w 2 127.0.0.1 %d", remotePort),
		))
		if cmdErr != nil {
			return false, nil //nolint:nilerr
		}

		return true, nil
	})
	require.NoError(t, err, "failed to connect to remote forwarded port from container")

	assert.Equal(t, "hello remote port forwarding\n", string(output))

	// Assert audit logs for remote port forwarding
	expectedUser := map[string]any{
		"id":       "user-ssh-remote-fwd",
		"username": "alex@acme.com",
		"groups":   []any{"Engineering"},
	}
	expectedGlobalRequest := map[string]any{
		"type":   "tcpip-forward",
		"source": "downstream",
		"target": "upstream",
	}
	testutil.AssertLogsForSSHGlobalRequest(t, env.logs, expectedUser, expectedGlobalRequest)

	expectedChannel := map[string]any{
		"type":   "forwarded-tcpip",
		"source": "upstream",
		"target": "downstream",
	}
	testutil.AssertLogsForSSHChannel(t, env.logs, expectedUser, expectedChannel)
}
