// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"gateway/internal/token"
	"gateway/test/fake"
)

const (
	network           = "acme"
	gatewayPort       = 8443
	gatewayHost       = "127.0.0.1"
	controllerPort    = 8080
	defaultUsername   = "alex@acme.com"
	gatewayConfigFile = "gateway-config.local.yaml"
)

// Before running this local dev client, Caddy must be already running. Run `caddy run` to start Caddy.
func main() {
	// Parse command line flags
	username := flag.String("username", defaultUsername, "Username to use for authentication")
	createKubeConfig := flag.Bool("create-kubeconfig", true, "Whether to create kubeConfig. If kubeConfig already exists, it will be overwritten")
	createKnownHosts := flag.Bool("create-ssh-known-hosts", true, "Whether to create SSH known_hosts. If known_hosts already exists, it will be overwritten")

	flag.Parse()

	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}

	defer func() {
		_ = logger.Sync()
	}()

	zap.ReplaceGlobals(logger)

	// Create a context that's canceled when SIGINT or SIGTERM is received
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		logger.Info("Received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	if err := createKindCluster(logger, *username); err != nil {
		logger.Fatal("Failed to create kind cluster", zap.Error(err))
	}

	if err = setupSSHServer(logger); err != nil {
		logger.Fatal("Failed to setup SSH server", zap.Error(err))
	}

	controller := fake.NewController(network, controllerPort)
	defer controller.Close()

	logger.Info("Controller is serving at", zap.String("url", controller.URL))

	user := &token.User{
		ID:       "user-1",
		Username: *username,
		Groups:   []string{"Developer", "OnCall"},
	}

	kubernetesClient := fake.NewClient(
		user,
		token.GeoIPLocation{},
		fmt.Sprintf("%s:%d", gatewayHost, gatewayPort),
		controller.URL,
		fmt.Sprintf("%s:%d", gatewayHost, kindPort),
		token.ResourceTypeKubernetes,
	)

	defer kubernetesClient.Close()

	logger.Info("Kubernetes fake Twingate client is serving at", zap.String("url", kubernetesClient.Address))

	if *createKubeConfig {
		if err := createKubeConfigFile("https://" + kubernetesClient.Address); err != nil {
			logger.Error("Failed to create kubeConfig", zap.Error(err))

			return
		}

		logger.Info("Created kubeConfig", zap.String("path", kubeConfigFile))
	}

	kindBearerToken, err := getKinDBearerToken()
	if err != nil {
		logger.Error("Failed to get bearer token", zap.Error(err))

		return
	}

	sshClient := fake.NewClient(
		user,
		token.GeoIPLocation{},
		fmt.Sprintf("%s:%d", gatewayHost, gatewayPort),
		controller.URL,
		fmt.Sprintf("%s:%d", gatewayHost, sshPort),
		token.ResourceTypeSSH,
	)

	defer sshClient.Close()

	logger.Info("SSH fake Twingate client is serving at", zap.String("address", sshClient.Address))

	if *createKnownHosts {
		err := createKnownHostsFile()
		if err != nil {
			logger.Error("Failed to add SSH CA to SSH known hosts file", zap.Error(err))

			return
		}

		logger.Info("Created SSH known_hosts file", zap.String("path", sshKnownHostFile))
	}

	echoServer := startEchoWebAppServer(logger)

	defer func() {
		if err := echoServer.server.Shutdown(context.Background()); err != nil {
			logger.Error("Failed to shutdown echo server", zap.Error(err))
		}
	}()

	webAppClient := fake.NewClient(
		user,
		token.GeoIPLocation{
			Lat:     37.5,
			Lon:     -122.4,
			Country: "US",
			Region:  "CA",
			City:    "San Mateo",
		},
		fmt.Sprintf("%s:%d", gatewayHost, gatewayPort),
		controller.URL,
		echoServer.address,
		token.ResourceTypeWebApp,
	)
	defer webAppClient.Close()

	logger.Info("Web app fake Twingate client is serving at", zap.String("address", webAppClient.Address))

	err = createLocalGatewayConfig(kindBearerToken)
	if err != nil {
		logger.Error("Failed to create local gateway config", zap.Error(err))

		return
	}

	_, sshClientPort, _ := net.SplitHostPort(sshClient.Address)

	gatewayRunCmd := "go run main.go start --debug --config " + gatewayConfigFile

	outputMsg := fmt.Sprintf(`
=====================================================
Twingate local dev environment running!
=====================================================

  Controller:           %s
  User:                 %s
  Client (Kubernetes):  %s
  Client (SSH):         %s
  Client (Web App):      %s

-----------------------------------------------------
1. Start the Gateway (in a separate terminal):

  %s

-----------------------------------------------------
2. Use kubectl with the local kubeconfig:

  kubectl --kubeconfig %s auth whoami

  Or set the context for your session:

  export KUBECONFIG=%s
  kubectl config use-context %s
  kubectl auth whoami

-----------------------------------------------------
3. SSH into the local server:

  ssh -p %s -o UserKnownHostsFile=%s 127.0.0.1

-----------------------------------------------------
4. Test Web App header forwarding:

  curl http://%s

-----------------------------------------------------
Press Ctrl+C to stop
=====================================================
`, controller.URL, user.Username, kubernetesClient.Address, sshClient.Address, webAppClient.Address,
		gatewayRunCmd,
		kubeConfigFile,
		kubeConfigFile, kindClusterName,
		sshClientPort, sshKnownHostFile,
		webAppClient.Address,
	)

	//nolint:forbidigo
	_, _ = fmt.Print(outputMsg)

	// Wait for context cancellation
	<-ctx.Done()
}

func createLocalGatewayConfig(kindBearerToken string) error {
	configTemplate := `
twingate:
  network: %s
  host: test
port: %d
tls:
  certificateFile: ./test/data/proxy/tls.crt
  privateKeyFile: ./test/data/proxy/tls.key
kubernetes:
  upstreams:
    - name: local-kind-cluster
      bearerToken: %s
      caFile: ./test/data/api_server/tls.crt
ssh:
  gateway:
    username: %s
    key:
      type: "ed25519"
    hostCertificate:
      ttl: "24h"
    userCertificate:
      ttl: "5m"
  ca:
    manual:
      privateKeyFile: ./test/data/ssh/ca/ca
webApp:
  headers:
    Authorization: "Bearer {{twingate.jwt}}"
    X-Twingate-User: "{{twingate.username}}"
    X-Twingate-Groups: "{{twingate.groups}}"
    X-Twingate-Client-Geo-LatLong: "{{twingate.clientGeoLatLong}}"
    X-Twingate-Client-Geo-City: "{{twingate.clientGeoCity}}"
    X-Twingate-Client-Geo-Region: "{{twingate.clientGeoRegion}}"
    X-Twingate-Client-Geo-Country: "{{twingate.clientGeoCountry}}"
`

	config := fmt.Sprintf(configTemplate, network, gatewayPort, kindBearerToken, sshUsername)

	err := os.WriteFile(gatewayConfigFile, []byte(config), 0600)
	if err != nil {
		return err
	}

	return nil
}
