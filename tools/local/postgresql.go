// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/wait"

	"gateway/test/integration/testutil"
)

const (
	// postgreSQLPort is the host port, chosen not to collide with a PostgreSQL already running on 5432.
	postgreSQLPort          = 15432
	postgreSQLContainerName = "gateway-local-postgresql"
	postgreSQLUsername      = "gateway"
	postgreSQLPassword      = "secret"
	postgreSQLDatabase      = "app"
	postgreSQLCredential    = "local"
)

func setupPostgreSQLServer(logger *zap.Logger) error {
	output, err := testutil.RunCommand(exec.Command("docker", "ps", "--filter", "name="+postgreSQLContainerName, "--format", "{{.Names}}"))
	if err != nil {
		return fmt.Errorf("failed to check if PostgreSQL server exists: %w", err)
	}

	if string(output) == postgreSQLContainerName+"\n" {
		logger.Info("PostgreSQL server already exists", zap.String("container_name", postgreSQLContainerName))

		return nil
	}

	logger.Info("Setting up PostgreSQL server")

	// #nosec G204 -- inputs are from trusted operator configuration
	runCmd := exec.Command("docker", "run", "-d",
		"-p", fmt.Sprintf("%d:5432", postgreSQLPort),
		"--name", postgreSQLContainerName,
		"--rm",
		"--env", "POSTGRES_USER="+postgreSQLUsername,
		"--env", "POSTGRES_PASSWORD="+postgreSQLPassword,
		"--env", "POSTGRES_DB="+postgreSQLDatabase,
		"postgres:17-alpine",
	)
	if _, err = testutil.RunCommand(runCmd); err != nil {
		return fmt.Errorf("failed to create PostgreSQL docker container: %w", err)
	}

	err = wait.PollUntilContextTimeout(context.Background(), time.Second, 60*time.Second, true, func(_ context.Context) (bool, error) {
		// The image first runs a temporary server on a Unix socket to initialise the database, so
		// readiness is checked over TCP, which only the final server listens on.
		_, err := testutil.RunCommand(exec.Command("docker", "exec", postgreSQLContainerName,
			"pg_isready", "-h", "127.0.0.1", "-U", postgreSQLUsername, "-d", postgreSQLDatabase))
		if err != nil {
			logger.Info("Waiting for PostgreSQL server to be ready...")

			return false, nil //nolint:nilerr
		}

		logger.Info("PostgreSQL server is running", zap.String("address", fmt.Sprintf("127.0.0.1:%d", postgreSQLPort)))

		return true, nil
	})
	if err != nil {
		return fmt.Errorf("failed to start PostgreSQL server: %w", err)
	}

	return nil
}
