// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"fmt"
	"net"

	"gateway/internal/token"
	"gateway/test/fake"
)

// User represents a user, its Kubectl instance and its fake Client.
type User struct {
	token.User

	Kubectl *Kubectl
	client  *fake.Client
}

// downstreamPort values are the client-facing ports used in the CONNECT request. They differ
// from the upstream ports the backends actually listen on, so the Gateway's port rewrite is
// exercised end-to-end: the client targets the downstream port and reaches the upstream port.
const (
	kubernetesDownstreamPort = 443
	sshDownstreamPort        = 22
	webAppDownstreamPort     = 80
)

func NewUser(user *token.User, gatewayPort int, kindAddress, controllerURL string) (*User, error) {
	client := fake.NewClient(
		user,
		token.GeoIPLocation{},
		fmt.Sprintf("127.0.0.1:%d", gatewayPort),
		controllerURL,
		kindAddress,
		kubernetesDownstreamPort,
		token.ResourceTypeKubernetes,
	)

	kubectl := &Kubectl{
		Options: KubectlOptions{
			ServerURL:                "https://" + client.Address,
			CertificateAuthorityFile: "../data/proxy/tls.crt",
		},
	}

	return &User{
		User:    *user,
		Kubectl: kubectl,
		client:  client,
	}, nil
}

func (u *User) Close() {
	u.client.Close()
}

// SSHUser represents a user, its SSH client and its fake Client.
type SSHUser struct {
	token.User

	SSH    *SSH
	client *fake.Client
}

func NewSSHUser(user *token.User, gatewayPort int, sshServerAddress, controllerURL, knownHostsFile string) (*SSHUser, error) {
	client := fake.NewClient(
		user,
		token.GeoIPLocation{},
		fmt.Sprintf("127.0.0.1:%d", gatewayPort),
		controllerURL,
		sshServerAddress,
		sshDownstreamPort,
		token.ResourceTypeSSH,
	)

	hostname, port, err := net.SplitHostPort(client.Address)
	if err != nil {
		return nil, err
	}

	return &SSHUser{
		User:   *user,
		SSH:    &SSH{username: user.Username, hostname: hostname, port: port, knownHostsFile: knownHostsFile},
		client: client,
	}, nil
}

func (u *SSHUser) Close() {
	u.client.Close()
}

// WebAppUser represents a user and its fake Client configured for WebApp proxying.
type WebAppUser struct {
	token.User

	URL    string
	client *fake.Client
}

func NewWebAppUser(user *token.User, geoIPLocation token.GeoIPLocation, gatewayPort int, upstreamAddress, controllerURL string) *WebAppUser {
	client := fake.NewClient(
		user,
		geoIPLocation,
		fmt.Sprintf("127.0.0.1:%d", gatewayPort),
		controllerURL,
		upstreamAddress,
		webAppDownstreamPort,
		token.ResourceTypeWebApp,
	)

	return &WebAppUser{
		User:   *user,
		URL:    "http://" + client.Address,
		client: client,
	}
}

func (u *WebAppUser) Close() {
	u.client.Close()
}
