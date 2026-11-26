// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	// The compat image includes the AWS CLI.
	flociImage       = "floci/floci:2.5.0-compat"
	flociAPIPort     = 4566
	flociIAMUserName = "gateway"
	flociIAMRoleName = "rds-login"

	RDSRegion         = "us-east-1"
	rdsInstanceID     = "gateway"
	rdsMasterUsername = "postgres"
	rdsMasterPassword = "master-secret"
)

// SetupFlociServer starts floci, an AWS emulator, with IAM enforcement on. It returns its container
// ID and the host port that serves its AWS API.
func SetupFlociServer(t *testing.T) (string, int) {
	t.Helper()

	ensureDockerImage(t, flociImage)
	ensureDockerImage(t, postgreSQLImage)

	// floci runs the instance's database in a container of its own, so it needs the socket of the
	// Docker daemon these tests use, which is not always /var/run/docker.sock.
	output, err := RunCommand(exec.Command("docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"))
	require.NoError(t, err, "failed to get Docker daemon socket")

	dockerSocket := strings.TrimPrefix(strings.TrimSpace(string(output)), "unix://")

	// floci serves its first RDS instance on port 7001. An IAM auth token is only valid for the
	// address the instance reports, so floci is told the address the Gateway connects to. IAM
	// enforcement makes floci refuse a token from a key whose policies do not allow rds-db:connect.
	//
	// #nosec G204 -- inputs are from trusted operator configuration
	output, err = RunCommand(exec.Command("docker", "run", "-d",
		"-p", "0:7001",
		"-p", fmt.Sprintf("0:%d", flociAPIPort),
		"-v", dockerSocket+":/var/run/docker.sock",
		"--name", "gateway-integration-test-floci",
		"-e", "FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true",
		"-e", "FLOCI_SERVICES_RDS_ENDPOINT_HOST=127.0.0.1",
		"-e", "FLOCI_SERVICES_RDS_DEFAULT_POSTGRES_IMAGE="+postgreSQLImage,
		flociImage,
	))
	require.NoError(t, err, "failed to create floci docker container")

	containerID := strings.TrimSpace(string(output))

	t.Cleanup(func() {
		// #nosec G204 -- output is a container ID returned by docker
		_, err = RunCommand(exec.Command("docker", "rm", "-vf", containerID))
		require.NoError(t, err, "failed to remove floci docker container")
	})

	// #nosec G204 -- output is a container ID returned by docker
	output, err = RunCommand(exec.Command("docker", "inspect", containerID,
		fmt.Sprintf("--format='{{(index (index .NetworkSettings.Ports \"%d/tcp\") 0).HostPort}}'", flociAPIPort),
	))
	require.NoError(t, err, "failed to get floci docker container port mappings")

	hostPort, err := strconv.Atoi(strings.Trim(string(output), "'\n"))
	require.NoError(t, err, "failed to parse floci host port")

	err = wait.PollUntilContextTimeout(t.Context(), time.Second, 30*time.Second, true, func(_ context.Context) (bool, error) {
		// #nosec G204 -- output is a container ID returned by docker
		_, err := RunCommand(exec.Command("docker", "exec", containerID, "aws", "sts", "get-caller-identity"))
		if err != nil {
			t.Log("Waiting for floci to be ready...")

			return false, nil //nolint:nilerr
		}

		return true, nil
	})
	require.NoError(t, err, "failed to start floci")

	return containerID, hostPort
}

// SetupFlociRDS creates an RDS PostgreSQL instance that has IAM database authentication on in the
// floci container. PostgreSQLUsername logs in to PostgreSQLDatabase with an IAM auth token. It
// returns the CA certificate file that verifies the instance and the instance's port.
func SetupFlociRDS(t *testing.T, containerID string) (string, int) {
	t.Helper()

	// #nosec G204 -- output is a container ID returned by docker
	output, err := RunCommand(exec.Command("docker", "exec", containerID,
		"aws", "rds", "create-db-instance",
		"--region", RDSRegion,
		"--db-instance-identifier", rdsInstanceID,
		"--db-instance-class", "db.t3.micro",
		"--engine", "postgres",
		"--master-username", rdsMasterUsername,
		"--master-user-password", rdsMasterPassword,
		"--db-name", PostgreSQLDatabase,
		"--enable-iam-database-authentication",
		"--query", "DBInstance.Endpoint.Port",
		"--output", "text",
	))
	require.NoError(t, err, "failed to create RDS instance")

	t.Cleanup(func() {
		// Removing floci does not remove the database container and volume it created.
		// #nosec G204 -- output is a container ID returned by docker
		_, err = RunCommand(exec.Command("docker", "exec", containerID,
			"aws", "rds", "delete-db-instance",
			"--region", RDSRegion,
			"--db-instance-identifier", rdsInstanceID,
			"--skip-final-snapshot",
		))
		require.NoError(t, err, "failed to delete RDS instance")
	})

	serverPort, err := strconv.Atoi(strings.TrimSpace(string(output)))
	require.NoError(t, err, "failed to parse RDS instance port")

	t.Logf("RDS instance is running at 127.0.0.1:%d", serverPort)

	conn, err := pgx.Connect(t.Context(), fmt.Sprintf("postgres://%s:%s@127.0.0.1:%d/%s?sslmode=disable",
		rdsMasterUsername, rdsMasterPassword, serverPort, PostgreSQLDatabase))
	require.NoError(t, err, "failed to connect to RDS instance as the master user")

	// RDS takes an IAM auth token only from a role that is granted rds_iam.
	_, err = conn.Exec(t.Context(), fmt.Sprintf("CREATE ROLE %s LOGIN; GRANT rds_iam TO %s", PostgreSQLUsername, PostgreSQLUsername))
	require.NoError(t, err, "failed to create the IAM database role")
	require.NoError(t, conn.Close(t.Context()))

	certificateFile := filepath.Join(t.TempDir(), "floci-root-ca.crt")

	// #nosec G204 -- output is a container ID returned by docker
	_, err = RunCommand(exec.Command("docker", "cp", containerID+":/app/data/tls/floci-root-ca.crt", certificateFile))
	require.NoError(t, err, "failed to copy floci CA certificate from docker container")

	return certificateFile, serverPort
}

// SetupFlociAssumeRole creates an IAM role that can log in to the RDS instance and an IAM user that
// can assume that role in the floci container. It returns the role's ARN and the user's access key.
func SetupFlociAssumeRole(t *testing.T, containerID string) (roleARN, accessKeyID, secretAccessKey string) {
	t.Helper()

	// #nosec G204 -- output is a container ID returned by docker
	output, err := RunCommand(exec.Command("docker", "exec", containerID,
		"aws", "iam", "create-user",
		"--user-name", flociIAMUserName,
		"--query", "User.Arn",
		"--output", "text",
	))
	require.NoError(t, err, "failed to create IAM user")

	userARN := strings.TrimSpace(string(output))

	// #nosec G204 -- inputs are from trusted operator configuration
	output, err = RunCommand(exec.Command("docker", "exec", containerID,
		"aws", "iam", "create-role",
		"--role-name", flociIAMRoleName,
		"--assume-role-policy-document", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":%q},"Action":"sts:AssumeRole"}]}`, userARN),
		"--query", "Role.Arn",
		"--output", "text",
	))
	require.NoError(t, err, "failed to create IAM role")

	roleARN = strings.TrimSpace(string(output))

	// #nosec G204 -- output is a container ID returned by docker
	_, err = RunCommand(exec.Command("docker", "exec", containerID,
		"aws", "iam", "put-role-policy",
		"--role-name", flociIAMRoleName,
		"--policy-name", "rds-connect",
		"--policy-document", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"rds-db:connect","Resource":"*"}]}`,
	))
	require.NoError(t, err, "failed to allow the IAM role to log in to RDS")

	// #nosec G204 -- inputs are from trusted operator configuration
	_, err = RunCommand(exec.Command("docker", "exec", containerID,
		"aws", "iam", "put-user-policy",
		"--user-name", flociIAMUserName,
		"--policy-name", "assume-role",
		"--policy-document", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":%q}]}`, roleARN),
	))
	require.NoError(t, err, "failed to allow the IAM user to assume the IAM role")

	// #nosec G204 -- output is a container ID returned by docker
	output, err = RunCommand(exec.Command("docker", "exec", containerID,
		"aws", "iam", "create-access-key",
		"--user-name", flociIAMUserName,
		"--query", "AccessKey.[AccessKeyId,SecretAccessKey]",
		"--output", "text",
	))
	require.NoError(t, err, "failed to create IAM access key")

	accessKey := strings.Fields(string(output))
	require.Len(t, accessKey, 2, "failed to parse IAM access key")

	return roleARN, accessKey[0], accessKey[1]
}
