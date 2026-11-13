// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
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

func NewUser(user *token.User, gatewayAddress, kindAddress, controllerURL string) (*User, error) {
	client := fake.NewClient(
		user,
		token.GeoIPLocation{},
		gatewayAddress,
		controllerURL,
		kindAddress,
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

func NewSSHUser(user *token.User, gatewayAddress, sshServerAddress, controllerURL, knownHostsFile string) (*SSHUser, error) {
	client := fake.NewClient(
		user,
		token.GeoIPLocation{},
		gatewayAddress,
		controllerURL,
		sshServerAddress,
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

func NewWebAppUser(user *token.User, geoIPLocation token.GeoIPLocation, gatewayAddress, upstreamAddress, controllerURL string, requestHeaderRewrites map[string]string) *WebAppUser {
	client := fake.NewClient(
		user,
		geoIPLocation,
		gatewayAddress,
		controllerURL,
		upstreamAddress,
		token.ResourceTypeWebApp,
		fake.WithRequestHeaderRewrites(requestHeaderRewrites),
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
