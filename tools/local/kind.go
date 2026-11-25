// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"time"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	kindcluster "sigs.k8s.io/kind/pkg/cluster"
	kindcmd "sigs.k8s.io/kind/pkg/cmd"

	"gateway/test/integration/testutil"
)

const (
	kubeConfigFile  = "kubeconfig-local"
	clusterName     = "gateway-local-development"
	kindClusterName = "kind-" + clusterName
	kindPort        = 6443
)

const setupYaml = `
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
  name: test-pod
spec:
  containers:
  - name: test-pod
    image: busybox
    command: ["sleep", "3600"]
---

# Setup role binding for test user
#
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: gateway-test-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: edit
subjects:
- kind: User
  name: %s
  apiGroup: rbac.authorization.k8s.io
`

var kindClusterYaml = fmt.Sprintf(`
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerPort: %d
nodes:
- role: control-plane
  extraMounts:
    - hostPath: ./test/data/api_server/tls.crt
      containerPath: /etc/kubernetes/pki/ca.crt
    - hostPath: ./test/data/api_server/tls.key
      containerPath: /etc/kubernetes/pki/ca.key
`, kindPort)

func createKindCluster(logger *zap.Logger, username string) error {
	provider := kindcluster.NewProvider(kindcluster.ProviderWithLogger(kindcmd.NewLogger()))

	existingClusters, err := provider.List()
	if err != nil {
		return err
	}

	if slices.Contains(existingClusters, clusterName) {
		logger.Info("Cluster already exists", zap.String("cluster", clusterName))

		return nil
	}

	logger.Info("Creating cluster", zap.String("cluster", clusterName))

	if err := provider.Create(clusterName, kindcluster.CreateWithRawConfig([]byte(kindClusterYaml))); err != nil {
		return err
	}

	kubectl := &testutil.Kubectl{
		Options: testutil.KubectlOptions{
			Context: kindClusterName,
		},
	}

	// It takes a while for KinD to create the `default` service account...
	logger.Info("Waiting for default service account to be created...")

	err = wait.PollUntilContextTimeout(
		context.Background(),
		time.Second,
		30*time.Second,
		true,
		func(ctx context.Context) (bool, error) {
			_, err = kubectl.CommandContext(ctx, "get", "serviceaccount", "default")
			if err != nil {
				return false, nil //nolint:nilerr
			}

			return true, nil
		},
	)
	if err != nil {
		logger.Fatal("Failed waiting for default service account", zap.Error(err))
	}

	_, err = kubectl.CommandWithInput(fmt.Sprintf(setupYaml, username), "apply", "-f", "-")
	if err != nil {
		logger.Fatal("Failed to apply setup YAML", zap.Error(err))
	}

	_, err = kubectl.Command("wait", "--for=condition=Ready", "pod/test-pod", "--timeout=30s")
	if err != nil {
		logger.Fatal("Failed waiting for busybox pod", zap.Error(err))
	}

	return nil
}

func getKinDBearerToken() (string, error) {
	kubectl := &testutil.Kubectl{
		Options: testutil.KubectlOptions{
			Context: kindClusterName,
		},
	}

	b64BearerToken, err := kubectl.Command(
		"get",
		"secret",
		"gateway-default-service-account",
		"-o",
		"jsonpath={.data.token}",
	)
	if err != nil {
		return "", err
	}

	bearerToken, err := base64.StdEncoding.DecodeString(string(b64BearerToken))
	if err != nil {
		return "", err
	}

	return string(bearerToken), nil
}

// createKubeConfigFile creates the KubeConfig file for the local dev environment.
// If kubeConfig file already exists, it will be overwritten.
func createKubeConfigFile(serverURL string) error {
	config := api.NewConfig()

	cluster := api.NewCluster()
	cluster.Server = serverURL
	cluster.InsecureSkipTLSVerify = true
	config.Clusters[clusterName] = cluster

	// Create auth info (no credentials needed as the fake client handles auth)
	authInfo := &api.AuthInfo{
		Token: "void",
	}
	config.AuthInfos[clusterName] = authInfo

	ctx := api.NewContext()
	ctx.Cluster = clusterName
	ctx.AuthInfo = clusterName
	config.Contexts[clusterName] = ctx

	config.CurrentContext = clusterName

	return clientcmd.WriteToFile(*config, kubeConfigFile)
}
