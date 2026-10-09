// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/wait"

	"gateway/test/data"
	"gateway/test/integration/testutil"
)

const (
	sshPort          = 2222
	sshContainerName = "gateway-local-ssh-server"
	sshKnownHostFile = "known_hosts_local"
	sshUsername      = "admin"
)

func setupSSHServer(logger *zap.Logger) error {
	output, err := testutil.RunCommand(exec.Command("docker", "ps", "--filter", "name="+sshContainerName, "--format", "{{.Names}}"))
	if err != nil {
		return fmt.Errorf("failed to check if SSH server exists: %w", err)
	}

	if string(output) == sshContainerName+"\n" {
		logger.Info("SSH server already exists", zap.String("container_name", sshContainerName))

		return nil
	}

	logger.Info("Setting up SSH server")

	uid, err := testutil.RunCommand(exec.Command("id", "-u"))
	if err != nil {
		return fmt.Errorf("failed to get user ID: %w", err)
	}

	gid, err := testutil.RunCommand(exec.Command("id", "-g"))
	if err != nil {
		return fmt.Errorf("failed to get group ID: %w", err)
	}

	// #nosec G204 -- inputs are from trusted operator configuration
	if _, err = testutil.RunCommand(exec.Command("docker", "run", "-d",
		"-p", fmt.Sprintf("%d:2222", sshPort),
		"--name", sshContainerName,
		"--rm",
		"--env", "PUID="+string(uid),
		"--env", "PGID="+string(gid),
		"--env", "USER_NAME="+sshUsername,
		"--env", "TZ=UTC",
		"--volume", "./test/data/ssh/sshd_test.conf:/config/sshd/sshd_config.d/sshd_test.conf",
		"lscr.io/linuxserver/openssh-server:latest",
	)); err != nil {
		return fmt.Errorf("failed to create OpenSSH server docker container: %w", err)
	}

	if _, err := testutil.RunCommand(exec.Command("docker", "cp", "./test/data/ssh/ca", sshContainerName+":/config/ca")); err != nil {
		return fmt.Errorf("failed to copy SSH CA public key: %w", err)
	}

	if _, err := testutil.RunCommand(exec.Command("docker", "cp", "./test/data/ssh/host", sshContainerName+":/config/host")); err != nil {
		return fmt.Errorf("failed to copy SSH host private key: %w", err)
	}

	// Private key permission must be 0600. Otherwise, it will be ignored by SSH.
	if _, err := testutil.RunCommand(exec.Command("docker", "exec", sshContainerName, "chmod", "0600", "/config/host/host")); err != nil {
		return fmt.Errorf("failed to change permission for SSH host private key: %w", err)
	}

	err = wait.PollUntilContextTimeout(context.Background(), time.Second, 10*time.Second, true, func(_ context.Context) (bool, error) {
		output, err := testutil.RunCommand(exec.Command("docker", "exec", sshContainerName, "pgrep", "sshd"))

		if err != nil || string(output) == "" {
			logger.Info("Waiting for SSH server to be ready...")

			return false, nil //nolint:nilerr
		}

		logger.Info("SSH server is running", zap.String("address", fmt.Sprintf("127.0.0.1:%d", sshPort)))

		return true, nil
	})
	if err != nil {
		return fmt.Errorf("failed to start SSH server: %w", err)
	}

	return nil
}

func createKnownHostsFile() error {
	certAuthorityLine := "@cert-authority * " + string(data.SSHCAPublicKey)

	// #nosec G304 -- file paths are from trusted operator configuration
	err := os.WriteFile(sshKnownHostFile, []byte(certAuthorityLine), 0600)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %w", sshKnownHostFile, err)
	}

	return nil
}
