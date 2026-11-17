// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/kind/pkg/cluster"

	kindcmd "sigs.k8s.io/kind/pkg/cmd"
)

// TestPodName is the name of the test pod created in the KinD cluster.
const TestPodName = "test-pod"

const kindClusterYaml = `
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
    - hostPath: ../data/api_server/tls.crt
      containerPath: /etc/kubernetes/pki/ca.crt
    - hostPath: ../data/api_server/tls.key
      containerPath: /etc/kubernetes/pki/ca.key
`

// setupYamlTemplate is used to generate the YAML for setting up resources in the KinD cluster.
const setupYamlTemplate = `
# Setup default service account for impersonation
#
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: gateway-impersonation
rules:
- apiGroups:
  - ""
  resources:
  - users
  - groups
  - serviceaccounts
  verbs:
  - impersonate
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: gateway-impersonation
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: gateway-impersonation
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
---
apiVersion: v1
kind: Secret
metadata:
  name: gateway-default-service-account
  annotations:
    kubernetes.io/service-account.name: default
type: kubernetes.io/service-account-token
---

# Setup a test pod
#
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
  - name: %s
    image: busybox
    command: ["/bin/sh"]
    args: ["-c", "while true; do cat /etc/hostname; sleep 0.5; done"]
---
`

func SetupKinD(t *testing.T) (*Kubectl, *rest.Config, string) {
	t.Helper()

	provider := cluster.NewProvider(cluster.ProviderWithLogger(kindcmd.NewLogger()))
	clusterName := "gateway-integration-test-" + strings.ToLower(t.Name())
	// kind locks the kubeconfig file without retrying, so concurrent clusters sharing the default
	// kubeconfig fail to create or delete.
	kubeconfigPath := filepath.Join(t.TempDir(), "kubeconfig")

	// Create the cluster
	err := provider.Create(clusterName,
		cluster.CreateWithRawConfig([]byte(kindClusterYaml)),
		cluster.CreateWithKubeconfigPath(kubeconfigPath),
	)
	require.NoError(t, err, "failed to create kind cluster")

	t.Cleanup(func() {
		err := provider.Delete(clusterName, kubeconfigPath)
		require.NoError(t, err, "failed to delete kind cluster")
	})

	// Get kubeconfig for KinD context
	kubeConfigStr, err := provider.KubeConfig(clusterName, false)
	require.NoError(t, err, "failed to get kubeconfig")

	kubeConfig, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeConfigStr))
	require.NoError(t, err, "failed to build config from kubeconfig")

	t.Log("KinD cluster was created at ", kubeConfig.Host)

	k := &Kubectl{
		Options: KubectlOptions{
			Kubeconfig: kubeconfigPath,
		},
	}

	// It takes a while for KinD to create the `default` service account...
	t.Log("Waiting for default service account to be created...")

	err = wait.PollUntilContextTimeout(t.Context(), time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err = k.CommandContext(ctx, "get", "serviceaccount", "default")
		if err != nil {
			return false, nil //nolint:nilerr
		}

		return true, nil
	})
	require.NoError(t, err, "failed waiting for default service account")

	setupYaml := fmt.Sprintf(setupYamlTemplate, TestPodName, TestPodName)
	_, err = k.CommandWithInput(setupYaml, "apply", "-f", "-")
	require.NoError(t, err, "failed to apply setup YAML")

	b64BearerToken, err := k.Command("get", "secret", "gateway-default-service-account", "-o", "jsonpath={.data.token}")
	require.NoError(t, err, "failed to get default service account's bearer token")

	bearerToken, err := base64.StdEncoding.DecodeString(string(b64BearerToken))
	require.NoError(t, err, "failed to decode bearer token")

	t.Log("Waiting for test-pod to be ready...")

	_, err = k.Command("wait", "--for=condition=Ready", "pod/"+TestPodName, "--timeout=30s")
	require.NoError(t, err, "failed waiting for busybox pod")

	return k, kubeConfig, string(bearerToken)
}

func CreateK8sRoleBinding(t *testing.T, kindKubectl *Kubectl, users []string) {
	t.Helper()

	yaml := `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: gateway-test-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: edit
subjects:
`

	var sb strings.Builder
	for _, user := range users {
		_, _ = fmt.Fprintf(&sb, `- kind: User
  name: "%s"
  apiGroup: rbac.authorization.k8s.io
`, user)
	}

	yaml += sb.String()

	_, err := kindKubectl.CommandWithInput(yaml, "apply", "-f", "-")
	require.NoError(t, err, "failed to apply setup YAML")
}
