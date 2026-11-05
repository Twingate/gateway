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

	"gateway/test/data"
)

const (
	postgreSQLImage           = "postgres:18.6-alpine"
	PostgreSQLUsername        = "gateway"
	PostgreSQLPassword        = "secret"
	PostgreSQLDatabase        = "app"
	PostgreSQLCertificateFile = "../data/proxy/tls.crt"

	// postgreSQLEntrypoint writes the certificate and key the image receives in its environment
	// where the server can read them then starts the server with TLS on.
	// Plaintext connections are still accepted.
	postgreSQLEntrypoint = `
		set -e

		printf '%s\n' "$SSL_CERT" > /var/lib/postgresql/server.crt
		printf '%s\n' "$SSL_KEY" > /var/lib/postgresql/server.key
		chown postgres:postgres /var/lib/postgresql/server.crt /var/lib/postgresql/server.key
		chmod 600 /var/lib/postgresql/server.key

		exec docker-entrypoint.sh postgres \
			-c ssl=on \
			-c ssl_cert_file=/var/lib/postgresql/server.crt \
			-c ssl_key_file=/var/lib/postgresql/server.key
	`
)

func SetupPostgreSQLServer(t *testing.T) (string, int) {
	t.Helper()

	const postgreSQLPort = 5432

	ensureDockerImage(t, postgreSQLImage)

	// #nosec G204 -- inputs are from trusted operator configuration
	output, err := RunCommand(exec.Command("docker", "run", "-d",
		"-p", fmt.Sprintf("0:%d", postgreSQLPort),
		"--name", "gateway-integration-test-postgresql",
		"--env", "POSTGRES_USER="+PostgreSQLUsername,
		"--env", "POSTGRES_PASSWORD="+PostgreSQLPassword,
		"--env", "POSTGRES_DB="+PostgreSQLDatabase,
		"--env", "SSL_CERT="+string(data.ProxyCert),
		"--env", "SSL_KEY="+string(data.ProxyKey),
		postgreSQLImage,
		"sh", "-c", postgreSQLEntrypoint,
	))
	require.NoError(t, err, "failed to create PostgreSQL docker container")

	containerID := strings.TrimSpace(string(output))

	// #nosec G204 -- output is a container ID returned by docker
	output, err = RunCommand(exec.Command("docker", "inspect", containerID,
		fmt.Sprintf("--format='{{(index (index .NetworkSettings.Ports \"%d/tcp\") 0).HostPort}}'", postgreSQLPort),
	))
	require.NoError(t, err, "failed to get docker container port mappings")

	serverPort, err := strconv.Atoi(strings.Trim(string(output), "'\n"))
	require.NoError(t, err, "failed to parse PostgreSQL server port")

	t.Cleanup(func() {
		// #nosec G204 -- output is a container ID returned by docker
		_, err = RunCommand(exec.Command("docker", "rm", "-vf", containerID))
		require.NoError(t, err, "failed to remove PostgreSQL docker container")
	})

	err = wait.PollUntilContextTimeout(t.Context(), time.Second, 60*time.Second, true, func(_ context.Context) (bool, error) {
		// The image first runs a temporary server on a Unix socket to initialize the database, so
		// readiness is checked over TCP, which only the final server listens on.
		// #nosec G204 -- output is a container ID returned by docker
		_, err = RunCommand(exec.Command("docker", "exec", containerID,
			"pg_isready", "-h", "127.0.0.1", "-U", PostgreSQLUsername, "-d", PostgreSQLDatabase))
		if err != nil {
			t.Log("Waiting for PostgreSQL server to be ready...")

			return false, nil //nolint:nilerr
		}

		t.Logf("PostgreSQL server is running at 127.0.0.1:%d", serverPort)

		return true, nil
	})
	require.NoError(t, err, "failed to start PostgreSQL server")

	return containerID, serverPort
}
