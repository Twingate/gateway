// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/kind/pkg/cluster"

	kindcmd "sigs.k8s.io/kind/pkg/cmd"

	"gateway/internal/token"
	"gateway/test/data"
	"gateway/test/fake"
	"gateway/test/integration/testutil"
)

// Prerequisites for running this test:
// - Caddy must be already running. Run `caddy run` to start Caddy.
// - Docker image must be already built and available in the local Docker daemon. Run `make build` to build Docker images.

const archARM64 = "arm64"

// The port that allows traffic from host to KinD node and to the Gateway NodePort service.
const nodePort = 31579

var kindClusterYaml = fmt.Sprintf(`
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: %d
    hostPort: %d
`, nodePort, nodePort)

func TestInCluster(t *testing.T) {
	// Start controller
	controller := fake.NewController("acme", 8080)
	defer controller.Close()

	t.Log("Controller is serving at", controller.URL)

	// Setup KinD
	clusterName := "gateway-e2e-test-" + strings.ToLower(t.Name())
	setupKinD(t, clusterName)
	createCaddyCACertConfigMap(t)

	dockerImageTag := getDockerImageTag(t)
	t.Log("Docker image tag:", dockerImageTag)

	loadDockerImageToKinD(t, clusterName, "twingate/gateway:"+dockerImageTag)

	// Deploy Gateway onto KinD using Helm
	deployHelmChart(t, clusterName, dockerImageTag)

	// Create user
	user, err := testutil.NewUser(
		&token.User{
			ID:       "user-1",
			Username: "alex@acme.com",
			Groups:   []string{"OnCall", "Engineering"},
		},
		nodePort,
		"kubernetes.default.svc.cluster.local:443",
		controller.URL,
	)
	require.NoError(t, err, "failed to create user")

	defer user.Close()

	// Test user authentication
	output, err := user.Kubectl.Command("auth", "whoami", "-o", "json")
	require.NoError(t, err, "failed to execute kubectl auth whoami")

	testutil.AssertWhoAmI(t, output, user.Username, append(user.Groups, "system:authenticated"))
}

func setupKinD(t *testing.T, clusterName string) {
	t.Helper()

	provider := cluster.NewProvider(cluster.ProviderWithLogger(kindcmd.NewLogger()))

	err := provider.Create(clusterName, cluster.CreateWithRawConfig([]byte(kindClusterYaml)))
	require.NoError(t, err, "failed to create KinD cluster")

	t.Cleanup(func() {
		err := provider.Delete(clusterName, "")
		require.NoError(t, err, "failed to delete KinD cluster")
	})
}

const caddyCACertificateURL = "http://localhost:2019/pki/ca/local/certificates"
const caddyCAConfigMapKey = "caddy-local-ca.crt"

func createCaddyCACertConfigMap(t *testing.T) {
	t.Helper()

	caCert := downloadCaddyCACert(t)

	// #nosec G204 -- Certificate comes from trusted local Caddy server
	cmd := exec.Command("kubectl", "create", "configmap", "caddy-local-ca", "--from-literal", fmt.Sprintf("%s=%s", caddyCAConfigMapKey, caCert))
	_, err := testutil.RunCommand(cmd)
	require.NoError(t, err, "failed to create ConfigMap for Caddy CA certificate")
}

func downloadCaddyCACert(t *testing.T) string {
	t.Helper()

	resp, err := http.Get(caddyCACertificateURL)
	require.NoError(t, err, "failed to download Caddy CA certificate")

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("received non-200 response when downloading Caddy CA certificate: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "failed to read Caddy CA certificate")

	return string(body)
}

// Returns the latest tag of the Gateway Docker image that uses the host machine's architecture.
// Only supports 2 architectures: arm64 (for local development on macOS) and amd64 (for CI running on Linux).
func getDockerImageTag(t *testing.T) string {
	t.Helper()

	var imageReference = "twingate/gateway:*-linux-"
	if runtime.GOARCH == archARM64 {
		imageReference += "arm64"
	} else {
		imageReference += "amd64"
	}

	cmd := exec.Command("docker", "images", "--filter", "reference="+imageReference, "--format", "{{.Tag}}")
	output, err := testutil.RunCommand(cmd)
	require.NoError(t, err, "failed to get docker image tag")

	// Parse output to handle multiple tags
	tags := strings.Fields(strings.TrimSpace(string(output)))
	require.NotEmpty(t, tags, "no docker image tags found for reference: %s", imageReference)

	// Return the first tag (most recently built) as `docker images` returns tags in reverse chronological order
	return tags[0]
}

func loadDockerImageToKinD(t *testing.T, clusterName, image string) {
	t.Helper()

	cmd := exec.Command("kind", "load", "docker-image", image, "-n", clusterName) //nolint:gosec // args are test-controlled
	_, err := testutil.RunCommand(cmd)
	require.NoError(t, err, "failed to load docker image to KinD")
}

const helmValuesYamlTemplate = `
twingate:
  network: acme
  host: test

kubernetes:
  enabled: true

image:
  repository: twingate/gateway
  tag: %s

volumes:
- name: caddy-local-ca-volume
  configMap:
    name: caddy-local-ca

volumeMounts:
- name: caddy-local-ca-volume
  mountPath: /etc/ssl/certs/caddy-local-ca.crt
  subPath: %s
  readOnly: true

hostAliases:
- ip: %s
  hostnames:
  - acme.test

service:
  type: NodePort
  nodePort: %d

tls:
  autoGenerated: false
  cert: %s
  key: %s
  ca: %s
`

func deployHelmChart(t *testing.T, clusterName, imageTag string) {
	t.Helper()

	tlsCert := data.ProxyCert
	tlsCertStr := strconv.Quote(string(tlsCert))

	tlsKey := data.ProxyKey
	tlsKeyStr := strconv.Quote(string(tlsKey))

	hostIP := getKindHostAccessIP(t, clusterName)
	t.Log("Host IP from within KinD cluster:", hostIP)

	helmValuesYaml := fmt.Sprintf(helmValuesYamlTemplate, imageTag, caddyCAConfigMapKey, hostIP, nodePort, tlsCertStr, tlsKeyStr, tlsCertStr)
	t.Log("Deploying Helm chart using the following values:\n", helmValuesYaml)

	cmd := exec.Command("helm", "install", "gateway", "../../deploy/gateway", "--wait", "-f", "-")
	cmd.Stdin = strings.NewReader(helmValuesYaml)
	output, err := testutil.RunCommand(cmd)
	require.NoError(t, err, "failed to deploy Helm chart")

	t.Log("Helm chart deployed successfully", string(output))
}

// This is the default Docker bridge network IP on Linux.
const kindHostAccessIPOnLinux = "172.17.0.1"

func getKindHostAccessIP(t *testing.T, clusterName string) string {
	t.Helper()

	if runtime.GOARCH != archARM64 {
		// When running on Linux, the host IP is fixed!
		return kindHostAccessIPOnLinux
	}

	// When running on macOS, find the host IP from `host.docker.internal` special hostname.

	// #nosec G204 -- clusterName comes from a trusted source (KinD cluster name)
	cmd := exec.Command("docker", "exec", clusterName+"-control-plane", "sh", "-c", "getent ahostsv4 host.docker.internal | awk '{ print $1; exit }'")
	output, err := testutil.RunCommand(cmd)
	require.NoError(t, err, "failed to get host IP")

	return strings.TrimSpace(string(output))
}
