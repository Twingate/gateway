// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"
)

// PostgresAuthMethod controls how the Postgres container is configured to
// authenticate clients — picks the auth method advertised to the gateway.
type PostgresAuthMethod string

const (
	PostgresAuthSCRAM     PostgresAuthMethod = "scram-sha-256"
	PostgresAuthCleartext PostgresAuthMethod = "password"
)

// SetupPostgresServer starts a PostgreSQL container configured for the given
// auth method. Returns (containerID, hostPort). The port is chosen by Docker
// to avoid collisions.
func SetupPostgresServer(t *testing.T, user, password, database string, authMethod PostgresAuthMethod) (string, int) {
	t.Helper()

	const (
		pgPort    = 5432
		imageName = "postgres:16"
	)

	// #nosec G204 -- inputs are from trusted test configuration
	_, err := RunCommand(exec.Command("docker", "pull", imageName))
	require.NoError(t, err, "failed to pull postgres docker image")

	// #nosec G204 -- inputs are from trusted test configuration
	output, err := RunCommand(exec.Command("docker", "run", "-d",
		"-p", fmt.Sprintf("0:%d", pgPort),
		"--name", "gateway-integration-test-postgres-"+strings.ToLower(t.Name()),
		"-e", "POSTGRES_USER="+user,
		"-e", "POSTGRES_PASSWORD="+password,
		"-e", "POSTGRES_DB="+database,
		"-e", "POSTGRES_HOST_AUTH_METHOD="+string(authMethod),
		"-e", "POSTGRES_INITDB_ARGS=--auth-host="+string(authMethod),
		imageName,
	))
	require.NoError(t, err, "failed to create postgres docker container")

	containerID := strings.TrimSpace(string(output))

	// #nosec G204 -- inputs are from trusted test configuration
	output, err = RunCommand(exec.Command("docker", "inspect", containerID,
		fmt.Sprintf("--format='{{(index (index .NetworkSettings.Ports \"%d/tcp\") 0).HostPort}}'", pgPort),
	))
	require.NoError(t, err, "failed to get docker container port mappings")

	serverPort, err := strconv.Atoi(strings.Trim(string(output), "'\n"))
	require.NoError(t, err, "failed to parse postgres host port")

	t.Cleanup(func() {
		// #nosec G204 -- containerID is returned by docker
		_, err = RunCommand(exec.Command("docker", "rm", "-vf", containerID))
		require.NoError(t, err, "failed to remove postgres docker container")
	})

	err = wait.PollUntilContextTimeout(t.Context(), time.Second, 30*time.Second, true, func(_ context.Context) (bool, error) {
		// pg_isready returns 0 when ready to accept connections.
		// #nosec G204 -- containerID is returned by docker
		_, err := RunCommand(exec.Command("docker", "exec", containerID, "pg_isready", "-U", user))
		if err != nil {
			t.Log("Waiting for PostgreSQL to be ready...")

			return false, nil //nolint:nilerr
		}

		t.Logf("PostgreSQL is running at 127.0.0.1:%d", serverPort)

		return true, nil
	})
	require.NoError(t, err, "postgres failed to become ready")

	return containerID, serverPort
}
