// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// netPipe is analogous to net.Pipe, but it uses a real loopback TCP connection, and therefore
// is buffered (net.Pipe deadlocks if both sides start with a write).
func netPipe(t *testing.T) (client, server net.Conn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close()

	client, err = net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	server, err = listener.Accept()
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	return client, server
}

// testSigner generates an ed25519 host/user key for test SSH endpoints.
func testSigner(t *testing.T) ssh.Signer {
	t.Helper()

	keyConf, err := newKeyConfig("ed25519", 0)
	require.NoError(t, err)

	signer, _, err := keyConf.Generate(rand.Reader)
	require.NoError(t, err)

	return signer
}

// sshPipe establishes a real SSH connection over netPipe and returns the client and server
// sides. Both sides are torn down on test cleanup when netPipe closes the underlying conns.
func sshPipe(t *testing.T) (client, server *connection) {
	t.Helper()

	clientNetConn, serverNetConn := netPipe(t)

	hostKey := testSigner(t)
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(hostKey)

	serverReady := make(chan *connection, 1)

	go func() {
		defer close(serverReady)

		conn, channels, requests, err := ssh.NewServerConn(serverNetConn, serverConfig)
		if err != nil {
			return
		}

		serverReady <- &connection{conn: conn, channels: channels, requests: requests}
	}()

	clientConfig := &ssh.ClientConfig{
		User:            "testuser",
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
	}

	conn, channels, requests, err := ssh.NewClientConn(clientNetConn, "", clientConfig)
	require.NoError(t, err)

	client = &connection{conn: conn, channels: channels, requests: requests}

	server, ok := <-serverReady
	require.True(t, ok, "server SSH handshake failed")

	return client, server
}
