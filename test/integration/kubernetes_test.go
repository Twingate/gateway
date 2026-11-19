// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/proxy"
	"gateway/internal/sessionrecorder"
	"gateway/internal/token"
	"gateway/test/fake"
	"gateway/test/integration/testutil"
)

const network = "acme"
const host = "test"

// TestKubernetes tests the following properties:
// - User's identity is correctly forwarded to the Kubernetes API server and logged.
// - REST API request and response are audited.
// - Streaming API request and its session recording are audited.
// - `kubectl cp` is audited without a session recording.
func TestKubernetes(t *testing.T) {
	const gatewayPort = 8443

	kindKubectl, kindKubeConfig, kindBearerToken := testutil.SetupKinD(t)

	kindURL, err := url.Parse(kindKubeConfig.Host)
	require.NoError(t, err, "failed to parse API server URL")

	// Start the Controller
	controller := fake.NewController(network, 8080)
	defer controller.Close()

	t.Log("Controller is serving at", controller.URL)

	config := gatewayconfig.Config{
		Twingate: gatewayconfig.TwingateConfig{
			Network: network,
			Host:    host,
		},
		Port:        gatewayPort,
		MetricsPort: 0,
		TLS: gatewayconfig.TLSConfig{
			Certificates: &gatewayconfig.TLSCertificateSources{
				Files: []gatewayconfig.TLSCertificateFileKeyPair{
					{
						CertificateFile: "../data/proxy/tls.crt",
						PrivateKeyFile:  "../data/proxy/tls.key",
					},
				},
			},
		},
		Kubernetes: &gatewayconfig.KubernetesConfig{
			Upstreams: []gatewayconfig.KubernetesUpstream{
				{
					Name:        "kind-cluster",
					BearerToken: kindBearerToken,
					CAFile:      "../data/api_server/tls.crt",
				},
			},
		},
	}

	logger, logs := testutil.NewObservedLogger()

	p, err := proxy.NewProxy(&config, prometheus.NewRegistry(), logger)
	require.NoError(t, err, "failed to create proxy")

	// Start the Gateway
	go func() {
		err := p.Start()
		t.Logf("Failed to start Gateway: %v", err)
	}()

	testutil.GatewayHealthCheck(t, gatewayPort)

	// Create a user
	user, err := testutil.NewUser(
		&token.User{
			ID:       "user-1",
			Username: "alex@acme.com",
			Groups:   []string{"OnCall", "Engineering"},
		},
		gatewayPort,
		kindURL.Host,
		controller.URL,
	)
	require.NoError(t, err, "failed to create user")

	defer user.Close()

	testutil.CreateK8sRoleBinding(t, kindKubectl, []string{user.Username})

	// Test `kubectl auth whoami`
	output, err := user.Kubectl.Command("auth", "whoami", "-o", "json")
	require.NoError(t, err, "failed to execute kubectl auth whoami")

	testutil.AssertWhoAmI(t, output, user.Username, append(user.Groups, "system:authenticated"))

	expectedUser := map[string]any{
		"id":       "user-1",
		"username": "alex@acme.com",
		"groups":   []any{"OnCall", "Engineering"},
	}
	testutil.AssertLogsForREST(t, logs, "/apis/authentication.k8s.io/v1/selfsubjectreviews", expectedUser, http.StatusCreated)

	// Test `kubectl exec`
	output, err = user.Kubectl.Command("exec", "test-pod", "--", "cat", "/etc/hostname")
	require.NoError(t, err, "failed to execute kubectl exec")

	assert.Equal(t, "test-pod\n", string(output))

	expectedHeader := sessionrecorder.AsciicastHeader{
		Version:   2,
		Width:     0,
		Height:    0,
		Timestamp: 0,
		Command:   "cat /etc/hostname",
		User:      expectedUser["username"].(string),
	}
	expectedEvents := []string{"", "test-pod\n"}
	testutil.AssertLogsForExecOrAttach(t, logs, "/api/v1/namespaces/default/pods/test-pod/exec?command=cat&command=%2Fetc%2Fhostname&container=test-pod&stderr=true&stdout=true", expectedUser, expectedHeader, expectedEvents)

	// Test `kubectl cp` from the pod
	copiedFile := filepath.Join(t.TempDir(), "hostname")

	_, err = user.Kubectl.Command("cp", "test-pod:/etc/hostname", copiedFile)
	require.NoError(t, err, "failed to execute kubectl cp from the pod")

	copiedContent, err := os.ReadFile(copiedFile) //nolint:gosec // The path is inside the test temporary directory
	require.NoError(t, err, "failed to read the copied file")
	assert.Equal(t, "test-pod\n", string(copiedContent))

	testutil.AssertLogsForExecWithoutRecording(t, logs, "/api/v1/namespaces/default/pods/test-pod/exec?command=tar&command=cf&command=-&command=%2Fetc%2Fhostname&container=test-pod&stderr=true&stdout=true", expectedUser)

	// Test `kubectl cp` to the pod
	_, err = user.Kubectl.Command("cp", copiedFile, "test-pod:/tmp/hostname")
	require.NoError(t, err, "failed to execute kubectl cp to the pod")

	testutil.AssertLogsForExecWithoutRecording(t, logs, "/api/v1/namespaces/default/pods/test-pod/exec?command=tar&command=-xmf&command=-&command=-C&command=%2Ftmp&container=test-pod&stderr=true&stdin=true&stdout=true", expectedUser)

	// Test `kubectl exec` with a `tar` command that `kubectl cp` does not run
	output, err = user.Kubectl.Command("exec", "test-pod", "--", "tar", "cvf", "/dev/null", "-C", "/tmp", "hostname")
	require.NoError(t, err, "failed to execute kubectl exec with tar")

	assert.Equal(t, "hostname\n", string(output))

	expectedHeader = sessionrecorder.AsciicastHeader{
		Version:   2,
		Width:     0,
		Height:    0,
		Timestamp: 0,
		Command:   "tar cvf /dev/null -C /tmp hostname",
		User:      expectedUser["username"].(string),
	}
	expectedEvents = []string{"", "hostname\n"}
	testutil.AssertLogsForExecOrAttach(t, logs, "/api/v1/namespaces/default/pods/test-pod/exec?command=tar&command=cvf&command=%2Fdev%2Fnull&command=-C&command=%2Ftmp&command=hostname&container=test-pod&stderr=true&stdout=true", expectedUser, expectedHeader, expectedEvents)

	// Test `kubectl attach`
	expectedHeader = sessionrecorder.AsciicastHeader{
		Version:   2,
		Width:     0,
		Height:    0,
		Timestamp: 0,
		User:      expectedUser["username"].(string),
	}
	expectedEvents = []string{"", "test-pod\n"}

	var exitError *exec.ExitError

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	output, err = user.Kubectl.CommandContext(ctx, "attach", "test-pod")
	// ExitError is expected here because the command gets killed because of the timeout
	require.ErrorAs(t, err, &exitError)
	require.Empty(t, exitError.Stderr, "failed to execute kubectl attach")

	assert.Contains(t, string(output), "test-pod\n")

	// Wait for the logs to be flushed
	time.Sleep(100 * time.Millisecond)

	testutil.AssertLogsForExecOrAttach(t, logs, "/api/v1/namespaces/default/pods/test-pod/attach?container=test-pod&stderr=true&stdout=true", expectedUser, expectedHeader, expectedEvents)
}
