// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"crypto/rand"
	"io"
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/connect"
	"gateway/internal/token"
)

var sshConfig = &gatewayconfig.SSHConfig{
	Gateway: gatewayconfig.SSHGatewayConfig{
		Username: "test-user",
	},
}

// newProxyConn builds a connect.ProxyConn over conn with test GAT claims and the given
// upstream address.
func newProxyConn(conn net.Conn, address string) *connect.ProxyConn {
	proxyConn := connect.NewProxyConn(conn, nil, nil, zap.NewNop(),
		connect.CreateProxyConnMetrics(prometheus.NewRegistry()))
	proxyConn.Claims = &token.GATClaims{}
	proxyConn.Address = address
	proxyConn.ID = "test-id"

	return proxyConn
}

// newDownstreamConn returns the two ends of the proxy's downstream connection; address is the
// upstream the proxy dials when serving the server end.
func newDownstreamConn(t *testing.T, address string) (client net.Conn, server *connect.ProxyConn) {
	t.Helper()

	clientConn, serverConn := loopbackConnPair(t)

	return clientConn, newProxyConn(serverConn, address)
}

// newTestProxy builds an SSHProxy in auto-generated CA mode with its downstream config ready.
func newTestProxy(t *testing.T) *SSHProxy {
	t.Helper()

	config, err := NewConfig(nil, sshConfig, zap.NewNop())
	require.NoError(t, err)

	proxy := NewProxy(*config)

	downstreamConfig, err := config.GetDownstreamConfig(t.Context())
	require.NoError(t, err)

	proxy.downstreamConfig = downstreamConfig

	return proxy
}

// gatewayUserCAPublicKey returns the public key of the CA that signs the Gateway's user
// certificates, so an in-memory upstream server can authenticate the Gateway.
func gatewayUserCAPublicKey(t *testing.T, proxy *SSHProxy) ssh.PublicKey {
	t.Helper()

	pub, err := proxy.config.caConfig.GatewayUserCA.publicKey(t.Context())
	require.NoError(t, err)

	return pub
}

// echoServer is an in-memory SSH server that authenticates the Gateway's user certificate and
// echoes session output back.
type echoServer struct {
	listener net.Listener
	addr     string
}

func newEchoServer(t *testing.T, userCAPub ssh.PublicKey) *echoServer {
	t.Helper()

	hostSigner, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return keysEqual(auth, userCAPub)
		},
	}

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: checker.Authenticate,
	}
	serverConfig.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { _ = listener.Close() })

	srv := &echoServer{listener: listener, addr: listener.Addr().String()}
	go srv.acceptLoop(serverConfig)

	return srv
}

func (s *echoServer) acceptLoop(config *ssh.ServerConfig) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		go handleConn(conn, config)
	}
}

func handleConn(conn net.Conn, config *ssh.ServerConfig) {
	sshConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()

		return
	}

	defer sshConn.Close()

	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported")

			continue
		}

		go handleSession(newChannel)
	}
}

func handleSession(newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}

	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case requestTypeExec:
			var payload execReq

			_ = ssh.Unmarshal(req.Payload, &payload)
			_ = req.Reply(true, nil)
			_, _ = io.WriteString(channel, payload.Command)
			sendExitStatus(channel, 0)

			return
		case requestTypeShell:
			_ = req.Reply(true, nil)
			_, _ = io.Copy(channel, channel) // echo stdin back to stdout
			sendExitStatus(channel, 0)

			return
		case requestTypePty, requestTypeWindowChange, "env":
			_ = req.Reply(true, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func sendExitStatus(channel ssh.Channel, code uint32) {
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: code}))
}

// loopbackConnPair returns the two ends of a real loopback TCP connection. SSH handshakes
// cannot run over net.Pipe (its writes are synchronous, so the mutual version/key exchange
// deadlocks); a buffered socket pair is required.
func loopbackConnPair(t *testing.T) (client, server net.Conn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}

	accepted := make(chan acceptResult, 1)

	go func() {
		conn, err := listener.Accept()
		accepted <- acceptResult{conn: conn, err: err}
	}()

	client, err = net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	result := <-accepted
	require.NoError(t, result.err)

	t.Cleanup(func() {
		_ = client.Close()
		_ = result.conn.Close()
	})

	return client, result.conn
}

// dialDownstream completes a real SSH client handshake through the proxy and returns the client.
func dialDownstream(t *testing.T, clientConn net.Conn, addr string) (*ssh.Client, error) {
	t.Helper()

	clientConfig := &ssh.ClientConfig{
		User: "client",
		// The test client does not verify the Gateway's host key.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	conn, channels, requests, err := ssh.NewClientConn(clientConn, addr, clientConfig)
	if err != nil {
		return nil, err
	}

	return ssh.NewClient(conn, channels, requests), nil
}

// testListener is a real loopback listener that presents accepted connections as connect.Conn.
// The proxy dials upstreamAddr for every accepted connection.
type testListener struct {
	net.Listener

	upstreamAddr string
}

func newTestListener(t *testing.T, upstreamAddr string) *testListener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { _ = listener.Close() })

	return &testListener{Listener: listener, upstreamAddr: upstreamAddr}
}

func (l *testListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return newProxyConn(conn, l.upstreamAddr), nil
}
