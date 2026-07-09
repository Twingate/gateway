// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"
)

func SetupVaultServer(t *testing.T) (string, int) {
	t.Helper()

	containerName := "gateway-integration-test-vault-" + strings.ToLower(t.Name())

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err := RunCommand(exec.Command("docker", "run", "-d",
		"--cap-add=IPC_LOCK",
		"-p", "0:8200",
		"--name", containerName,
		"-e", "VAULT_DEV_ROOT_TOKEN_ID=root",
		"-e", "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		"-e", "VAULT_TOKEN=root",
		"-e", "VAULT_ADDR=http://127.0.0.1:8200",
		"hashicorp/vault:1.21.4",
		"server", "-dev",
	))
	require.NoError(t, err, "failed to create Vault container")

	t.Cleanup(func() {
		// #nosec G204 -- inputs are from trusted operator configuration
		_, err = RunCommand(exec.Command("docker", "rm", "-vf", containerName))
		require.NoError(t, err, "failed to remove Vault docker container")
	})

	// #nosec G204 -- inputs are from trusted operator configuration
	output, err := RunCommand(exec.Command("docker", "inspect", containerName,
		"--format='{{(index (index .NetworkSettings.Ports \"8200/tcp\") 0).HostPort}}'",
	))
	require.NoError(t, err, "failed to get Vault docker container port mappings")

	serverPort, err := strconv.Atoi(strings.Trim(string(output), "'\n"))
	require.NoError(t, err, "failed to parse Vault server port")

	err = wait.PollUntilContextTimeout(t.Context(), time.Second, 10*time.Second, true, func(_ context.Context) (bool, error) {
		// #nosec G204 -- inputs are from trusted operator configuration
		_, err := RunCommand(exec.Command("docker", "exec", containerName, "vault", "status"))
		if err != nil {
			t.Log("Waiting for Vault server to be ready...")

			return false, nil //nolint:nilerr
		}

		t.Logf("Vault server is running at http://127.0.0.1:%d", serverPort)

		return true, nil
	})
	require.NoError(t, err, "failed to start Vault server")

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err = RunCommand(exec.Command("docker", "exec", containerName, "vault", "secrets", "enable", "-path=ssh", "ssh"))
	require.NoError(t, err, "failed to enable SSH secrets engine in Vault")

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err = RunCommand(exec.Command("docker", "cp", "../data/ssh/ca", containerName+":/tmp/ca"))
	require.NoError(t, err, "failed to copy SSH CA keys to Vault container")

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err = RunCommand(exec.Command("docker", "exec", containerName,
		"vault", "write", "ssh/config/ca",
		"private_key=@/tmp/ca/ca",
		"public_key=@/tmp/ca/ca.pub",
	))
	require.NoError(t, err, "failed to configure SSH CA in Vault")

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err = RunCommand(exec.Command("docker", "exec", containerName,
		"vault", "write", "ssh/roles/gateway-signer",
		"key_type=ca",
		"allow_user_certificates=true",
		"allow_host_certificates=true",
		"allowed_extensions=permit-port-forwarding,permit-pty,permit-user-rc",
		"allow_empty_principals=true",
		"allowed_users=admin",
	))
	require.NoError(t, err, "failed to create SSH signing role in Vault")

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err = RunCommand(exec.Command("docker", "exec", containerName,
		"sh", "-c", `vault policy write integration-test - <<EOF
path "ssh/sign/*" {
  capabilities = ["create", "update"]
}
path "ssh/config/ca" {
  capabilities = ["read"]
}
EOF`))
	require.NoError(t, err, "failed to create Vault policy")

	return containerName, serverPort
}

func SetupVaultToken(t *testing.T, containerName string) string {
	t.Helper()

	// #nosec G204 -- inputs are from trusted operator configuration
	output, err := RunCommand(exec.Command("docker", "exec", containerName,
		"vault", "token", "create", "-field=token", "-policy=integration-test",
	))
	require.NoError(t, err, "failed to create Vault token")

	token := strings.TrimSpace(string(output))

	t.Log("Vault token created")

	return token
}

func SetupVaultAppRole(t *testing.T, containerName string) (roleID string, secretID string) {
	t.Helper()

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err := RunCommand(exec.Command("docker", "exec", containerName, "vault", "auth", "enable", "approle"))
	require.NoError(t, err, "failed to enable AppRole auth in Vault")

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err = RunCommand(exec.Command("docker", "exec", containerName,
		"vault", "write", "auth/approle/role/gateway",
		"token_policies=integration-test",
	))
	require.NoError(t, err, "failed to create AppRole role in Vault")

	// #nosec G204 -- inputs are from trusted operator configuration
	output, err := RunCommand(exec.Command("docker", "exec", containerName,
		"vault", "read", "-field=role_id", "auth/approle/role/gateway/role-id",
	))
	require.NoError(t, err, "failed to read AppRole role-id from Vault")

	roleID = strings.TrimSpace(string(output))

	// #nosec G204 -- inputs are from trusted operator configuration
	output, err = RunCommand(exec.Command("docker", "exec", containerName,
		"vault", "write", "-field=secret_id", "-f", "auth/approle/role/gateway/secret-id",
	))
	require.NoError(t, err, "failed to generate AppRole secret-id from Vault")

	secretID = strings.TrimSpace(string(output))

	t.Logf("Vault AppRole configured: roleID=%s", roleID)

	return roleID, secretID
}
