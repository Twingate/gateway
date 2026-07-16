// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/ssh"

	vault "github.com/hashicorp/vault/api"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/connect"
	"gateway/internal/token"
)

func TestProxy_ProxiesConnection(t *testing.T) {
	// The one intentional overlap with the lower layers: a real client handshake through the
	// accept loop, then a direct-tcpip round-trip to the echo upstream, proving the full wiring.
	sshProxy := newTestProxy(t)
	upstream := newEchoServer(t, caPublicKey(t, sshProxy.config.caConfig.GatewayUserCA))
	listener := newTestListener(t, upstream.addr)

	startDone := make(chan error, 1)

	go func() {
		startDone <- sshProxy.Start(t.Context(), listener)
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	// The handshake also proves both auth legs: dialDownstream verifies the proxy's host
	// certificate, and the upstream authenticates the proxy's user certificate.
	client, err := dialDownstream(t, sshProxy, clientConn)
	require.NoError(t, err)

	tunnel, err := client.Dial("tcp", "10.0.0.1:80")
	require.NoError(t, err)

	_, err = tunnel.Write([]byte("ping"))
	require.NoError(t, err)
	assert.Equal(t, "ping", string(readInFull(t, tunnel, len("ping"))))

	// The identity the upstream saw is the proxy's, not the downstream client's.
	username, userCert := upstream.identity()
	assert.Equal(t, testProxyUsername, username)
	require.NotNil(t, userCert)
	assert.Equal(t, []string{testProxyUsername}, userCert.ValidPrincipals)

	require.NoError(t, client.Close())

	// The served connection is removed from the map once serving completes.
	require.Eventually(t, func() bool {
		return connCount(sshProxy) == 0
	}, testTimeout, 10*time.Millisecond, "served connection was not removed from the map")

	// Closing the listener makes Accept return net.ErrClosed, so Start returns cleanly.
	require.NoError(t, listener.Close())
	require.NoError(t, waitErr(t, startDone))
}

func TestProxy_StartFailure(t *testing.T) {
	// Start runs its CA and downstream-config setup synchronously and returns any failure
	// before the accept loop, so these cases call it directly and assert the returned error.
	tests := []struct {
		name    string
		setup   func(t *testing.T, caConfig *caConfig)
		wantErr string
	}{
		{
			name: "CA start failure",
			setup: func(t *testing.T, caConfig *caConfig) {
				t.Helper()

				authMethod, err := newAppRoleAuthMethod(&gatewayconfig.SSHCAVaultAppRoleConfig{
					RoleID:   "role-id",
					SecretID: "secret-id",
				})
				require.NoError(t, err)

				caConfig.vault = &Vault{
					client:     newDeadVaultCA(t).client,
					authMethod: authMethod,
					logger:     zap.NewNop(),
				}
			},
			wantErr: "failed to login to Vault",
		},
		{
			name: "downstream config failure",
			setup: func(t *testing.T, caConfig *caConfig) {
				t.Helper()

				caConfig.GatewayHostCA = &stubCA{
					signer:     testSigner(t),
					errOnCalls: map[int]error{1: errors.New("sign failed")},
				}
			},
			wantErr: "host cert signer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sshProxy := newTestProxy(t)
			tt.setup(t, sshProxy.config.caConfig)

			err := sshProxy.Start(t.Context(), newTestListener(t, "unused:22"))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestProxy_AcceptError(t *testing.T) {
	// A non-ErrClosed accept error is logged and stops the loop.
	core, logs := observer.New(zap.ErrorLevel)
	sshProxy := newTestProxyWithLogger(t, zap.New(core))

	listener := newTestListener(t, "unused:22")

	// An already-expired deadline makes the real listener's Accept fail with a deadline error,
	// which is not net.ErrClosed.
	tcpListener, ok := listener.Listener.(*net.TCPListener)
	require.True(t, ok)
	require.NoError(t, tcpListener.SetDeadline(time.Now()))

	startDone := make(chan error, 1)

	go func() {
		startDone <- sshProxy.Start(t.Context(), listener)
	}()

	require.NoError(t, waitErr(t, startDone))

	assert.NotEmpty(t, logs.FilterMessage("Failed to accept incoming connection").All())
}

func TestProxy_ServeConnPanicRecovered(t *testing.T) {
	// A panic while serving one connection is recovered: the accept loop keeps running and
	// the next connection is served end to end.
	sshProxy := newTestProxy(t)
	upstream := newEchoServer(t, caPublicKey(t, sshProxy.config.caConfig.GatewayUserCA))
	listener := newTestListener(t, upstream.addr)
	listener.panicConns = 1

	startDone := make(chan error, 1)

	go func() {
		startDone <- sshProxy.Start(t.Context(), listener)
	}()

	// The first connection panics the proxy's serving goroutine...
	panicConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	t.Cleanup(func() { _ = panicConn.Close() })

	// ...and the proxy still proxies the next connection.
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	client, err := dialDownstream(t, sshProxy, clientConn)
	require.NoError(t, err)

	tunnel, err := client.Dial("tcp", "10.0.0.1:80")
	require.NoError(t, err)

	_, err = tunnel.Write([]byte("ping"))
	require.NoError(t, err)
	assert.Equal(t, "ping", string(readInFull(t, tunnel, len("ping"))))

	require.NoError(t, client.Close())
	require.NoError(t, listener.Close())
	require.NoError(t, waitErr(t, startDone))
}

func TestCloseOnPanic_CleanupPanicRecovered(t *testing.T) {
	// closeOnPanic is the outermost defer in every serving goroutine, so a panic in its
	// cleanup must be recovered too rather than escape and crash the process.
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core)

	require.NotPanics(t, func() {
		defer closeOnPanic(logger, func() { panic("cleanup boom") })

		panic("serve boom")
	})

	assert.Equal(t, 2, logs.Len())
	assert.Equal(t, "Recovered from panic", logs.All()[0].Message)
	assert.Equal(t, "Recovered from panic during cleanup", logs.All()[1].Message)
}

func TestProxy_DownstreamHandshakeFailure(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T, clientConn net.Conn)
	}{
		{
			name: "client sends non-SSH bytes",
			run: func(t *testing.T, clientConn net.Conn) {
				t.Helper()

				// A version line followed by a garbage packet whose declared length is
				// over the protocol maximum, which the key exchange rejects (a bare garbage
				// line would leave the server waiting for a packet).
				garbagePacket := append([]byte("SSH-2.0-garbage\r\n"), bytes.Repeat([]byte{0xff}, 32)...)

				_, err := clientConn.Write(garbagePacket)
				require.NoError(t, err)
			},
		},
		{
			name: "client closes before handshaking",
			run: func(t *testing.T, clientConn net.Conn) {
				t.Helper()

				require.NoError(t, clientConn.Close())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sshProxy := newTestProxy(t)
			clientConn, serverConn := newDownstreamConn(t, "unused:22")

			serveDone := make(chan error, 1)

			go func() {
				serveDone <- sshProxy.serveConn(t.Context(), serverConn)
			}()

			tt.run(t, clientConn)

			// The handshake error is surfaced, the connection is closed and never tracked.
			require.Error(t, waitErr(t, serveDone))
			assertNetConnClosed(t, clientConn)
			assert.Zero(t, connCount(sshProxy))
		})
	}
}

func TestProxy_UpstreamFailures(t *testing.T) {
	// Each case breaks one rung of the upstream ladder with a real failure mechanism; the
	// downstream handshake succeeds first, then the error is surfaced, the downstream connection
	// is torn down, and nothing is left tracked.
	tests := []struct {
		name    string
		setup   func(t *testing.T, sshProxy *SSHProxy) string
		wantErr string
	}{
		{
			name: "upstream config build failure",
			setup: func(t *testing.T, sshProxy *SSHProxy) string {
				t.Helper()

				// The proxy signs a fresh user certificate per connection; a stub CA that
				// fails to sign breaks that before anything is dialed.
				sshProxy.config.caConfig.GatewayUserCA = &stubCA{
					signer:     testSigner(t),
					errOnCalls: map[int]error{1: errors.New("sign failed")},
				}

				return "unused:22"
			},
			wantErr: "failed to sign user certificate",
		},
		{
			name: "upstream dial failure",
			setup: func(t *testing.T, _ *SSHProxy) string {
				t.Helper()

				return closedPort(t)
			},
			wantErr: "connection refused",
		},
		{
			name: "upstream SSH handshake failure",
			setup: func(t *testing.T, _ *SSHProxy) string {
				t.Helper()

				// The upstream accepts the TCP connection then closes it without an SSH
				// handshake.
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)

				t.Cleanup(func() { _ = listener.Close() })

				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}

					_ = conn.Close()
				}()

				return listener.Addr().String()
			},
			wantErr: "ssh: handshake failed",
		},
		{
			name: "upstream host key not trusted",
			setup: func(t *testing.T, sshProxy *SSHProxy) string {
				t.Helper()

				// The proxy requires host certificates from this CA, but the upstream presents
				// a plain host key, so host verification fails.
				sshProxy.config.caConfig.UpstreamHostCA = &embeddedCA{signer: testSigner(t)}

				return newEchoServer(t, caPublicKey(t, sshProxy.config.caConfig.GatewayUserCA)).addr
			},
			wantErr: "ssh: handshake failed",
		},
		{
			name: "upstream rejects the proxy's user certificate",
			setup: func(t *testing.T, _ *SSHProxy) string {
				t.Helper()

				// The upstream trusts a different user CA than the one signing the proxy's
				// certificates.
				return newEchoServer(t, testSigner(t).PublicKey()).addr
			},
			wantErr: "unable to authenticate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sshProxy := newTestProxy(t)
			upstreamAddr := tt.setup(t, sshProxy)

			clientConn, serverConn := newDownstreamConn(t, upstreamAddr)

			serveDone := make(chan error, 1)

			go func() {
				serveDone <- sshProxy.serveConn(t.Context(), serverConn)
			}()

			// The downstream handshake succeeds; the proxy fails only at the upstream step.
			client, err := dialDownstream(t, sshProxy, clientConn)
			require.NoError(t, err)

			require.ErrorContains(t, waitErr(t, serveDone), tt.wantErr)

			// The downstream connection is torn down and was never tracked.
			assertConnClosed(t, client.Conn)
			assert.Zero(t, connCount(sshProxy))
		})
	}
}

func TestProxy_RejectsWhenShuttingDown(t *testing.T) {
	sshProxy := newTestProxy(t)
	sshProxy.Shutdown(t.Context())

	clientConn, serverConn := newDownstreamConn(t, "unused:22")

	require.ErrorIs(t, sshProxy.serveConn(t.Context(), serverConn), errShuttingDown)
	assertNetConnClosed(t, clientConn)
}

func TestProxy_Shutdown_ClosesActiveConnection(t *testing.T) {
	sshProxy := newTestProxy(t)
	upstream := newEchoServer(t, caPublicKey(t, sshProxy.config.caConfig.GatewayUserCA))

	clientConn, serverConn := newDownstreamConn(t, upstream.addr)

	serveDone := make(chan error, 1)

	go func() {
		serveDone <- sshProxy.serveConn(t.Context(), serverConn)
	}()

	client, err := dialDownstream(t, sshProxy, clientConn)
	require.NoError(t, err)

	// The connection pair is tracked once both handshakes complete.
	require.Eventually(t, func() bool {
		return connCount(sshProxy) == 1
	}, testTimeout, 10*time.Millisecond, "connection was not tracked")

	sshProxy.Shutdown(t.Context())

	// Shutdown returns only after the connection finished serving and untracked itself.
	assert.Zero(t, connCount(sshProxy))
	assertConnClosed(t, client.Conn)
	require.NoError(t, waitErr(t, serveDone))
}

// testProxyUsername is the username the test proxy presents to upstream servers.
const testProxyUsername = "proxy-user"

// newTestProxy builds an SSHProxy in manual CA mode with its downstream config ready, so tests
// can drive Serve/serveConn directly without going through Start. The proxy logs to a nop
// logger: the host-cert renewal goroutine outlives the test and logs its shutdown when
// t.Context() is canceled, which a t-bound logger would race with.
func newTestProxy(t *testing.T) *SSHProxy {
	t.Helper()

	return newTestProxyWithLogger(t, zap.NewNop())
}

// newTestProxyWithLogger is newTestProxy logging to the given logger, so a test can assert on
// log output.
func newTestProxyWithLogger(t *testing.T, logger *zap.Logger) *SSHProxy {
	t.Helper()

	config, err := NewConfig(nil, &gatewayconfig.SSHConfig{
		CA: gatewayconfig.SSHCAConfig{
			Manual: &gatewayconfig.SSHCAManualConfig{PrivateKeyFile: "../../test/data/ssh/ca/ca"},
		},
		Gateway: gatewayconfig.SSHGatewayConfig{Username: testProxyUsername},
	}, logger)
	require.NoError(t, err)

	sshProxy := NewProxy(*config)

	downstreamConfig, err := config.GetDownstreamConfig(t.Context())
	require.NoError(t, err)

	sshProxy.downstreamConfig = downstreamConfig

	return sshProxy
}

// caPublicKey returns the public key of the given certificate authority.
func caPublicKey(t *testing.T, authority ca) ssh.PublicKey {
	t.Helper()

	pub, err := authority.publicKey(t.Context())
	require.NoError(t, err)

	return pub
}

// echoServer is a minimal in-memory upstream SSH server: it authenticates the proxy's user
// certificate against the user CA it trusts (capturing the presented identity), accepts
// direct-tcpip channels whose bytes it echoes back, and discards everything else.
type echoServer struct {
	addr string

	mu       sync.Mutex
	username string
	userCert *ssh.Certificate
}

func newEchoServer(t *testing.T, userCAPub ssh.PublicKey) *echoServer {
	t.Helper()

	server := &echoServer{}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return keysEqual(auth, userCAPub)
		},
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			permissions, err := checker.Authenticate(meta, key)
			if err != nil {
				return nil, err
			}

			server.captureIdentity(meta.User(), key)

			return permissions, nil
		},
	}
	config.AddHostKey(testSigner(t))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { _ = listener.Close() })

	server.addr = listener.Addr().String()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		server.serve(conn, config)
	}()

	return server
}

func (s *echoServer) serve(netConn net.Conn, config *ssh.ServerConfig) {
	conn, channels, requests, err := ssh.NewServerConn(netConn, config)
	if err != nil {
		_ = netConn.Close()

		return
	}

	defer conn.Close()

	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "direct-tcpip" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only direct-tcpip channels are supported")

			continue
		}

		ch, chRequests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go ssh.DiscardRequests(chRequests)

		go func() {
			defer ch.Close()

			_, _ = io.Copy(ch, ch)
		}()
	}
}

// captureIdentity records the username and the user certificate presented during authentication.
func (s *echoServer) captureIdentity(username string, key ssh.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.username = username
	s.userCert, _ = key.(*ssh.Certificate)
}

// identity returns the username and user certificate captured during public-key authentication.
func (s *echoServer) identity() (username string, userCert *ssh.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.username, s.userCert
}

// newProxyConn wraps conn in the connect.ProxyConn the proxy serves, with test GAT claims and
// the address of the upstream the proxy dials.
func newProxyConn(conn net.Conn, upstreamAddr string) *connect.ProxyConn {
	proxyConn := connect.NewProxyConn(conn, nil, nil, zap.NewNop(),
		connect.CreateProxyConnMetrics(prometheus.NewRegistry()))
	proxyConn.Claims = &token.GATClaims{}
	proxyConn.Address = upstreamAddr
	proxyConn.ID = "test-conn-id"

	return proxyConn
}

// newDownstreamConn returns the two ends of the proxy's downstream connection: the raw client
// end and the server end wrapped as the connect.Conn the proxy serves; upstreamAddr is the
// upstream the proxy dials.
func newDownstreamConn(t *testing.T, upstreamAddr string) (client net.Conn, server *connect.ProxyConn) {
	t.Helper()

	clientConn, serverConn := netPipe(t)

	return clientConn, newProxyConn(serverConn, upstreamAddr)
}

// testListener is a real loopback listener presenting accepted connections as the connect.Conn
// values the proxy's accept loop expects; the proxy dials upstreamAddr for each of them.
type testListener struct {
	net.Listener

	upstreamAddr string

	// panicConns is how many accepted connections to wrap as panickingConn, so the proxy's
	// serving goroutine panics on them.
	panicConns int
}

// panickingConn panics when the proxy starts serving it, so the accept loop's recovery is
// exercised without depending on any production nil-deref.
type panickingConn struct{ connect.Conn }

func (panickingConn) GATClaims() *token.GATClaims { panic("injected serve panic") }

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

	proxyConn := newProxyConn(conn, l.upstreamAddr)

	if l.panicConns > 0 {
		l.panicConns--

		return panickingConn{proxyConn}, nil
	}

	return proxyConn, nil
}

// dialDownstream completes a real SSH client handshake with the proxy over clientConn,
// verifying the proxy's host certificate against its host CA, and returns the SSH client.
func dialDownstream(t *testing.T, sshProxy *SSHProxy, clientConn net.Conn) (*ssh.Client, error) {
	t.Helper()

	hostCAPub := caPublicKey(t, sshProxy.config.caConfig.GatewayHostCA)
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return keysEqual(auth, hostCAPub)
		},
	}

	clientConfig := &ssh.ClientConfig{
		User:              "downstream-client",
		HostKeyCallback:   checker.CheckHostKey,
		HostKeyAlgorithms: []string{ssh.CertAlgoED25519v01},
	}

	conn, channels, requests, err := ssh.NewClientConn(clientConn, "upstream:22", clientConfig)
	if err != nil {
		return nil, err
	}

	return ssh.NewClient(conn, channels, requests), nil
}

// closedPort reserves a loopback address and closes its listener, so connecting to it is
// refused immediately.
func closedPort(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := listener.Addr().String()
	require.NoError(t, listener.Close())

	return addr
}

// newDeadVaultCA returns a vaultCA whose client points at a closed port with retries disabled,
// so its publicKey and sign calls fail fast.
func newDeadVaultCA(t *testing.T) *vaultCA {
	t.Helper()

	client, err := vault.NewClient(vault.DefaultConfig())
	require.NoError(t, err)
	require.NoError(t, client.SetAddress("http://"+closedPort(t)))
	client.SetMaxRetries(0)

	return &vaultCA{client: client, mount: "ssh", role: "test"}
}

// waitErr returns the error delivered on done, failing the test if none arrives within
// testTimeout.
func waitErr(t *testing.T, done <-chan error) error {
	t.Helper()

	select {
	case err := <-done:
		return err
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for a result")

		return nil
	}
}

// assertNetConnClosed fails the test unless conn drains to close (EOF or reset) within
// testTimeout.
func assertNetConnClosed(t *testing.T, conn net.Conn) {
	t.Helper()

	// Setting a deadline on an already-closed connection fails with net.ErrClosed, which is
	// itself proof of closure.
	if err := conn.SetReadDeadline(time.Now().Add(testTimeout)); errors.Is(err, net.ErrClosed) {
		return
	}

	_, err := io.Copy(io.Discard, conn)
	assert.NotErrorIs(t, err, os.ErrDeadlineExceeded, "connection was not closed")
}

// connCount returns the number of connections the proxy is currently tracking.
func connCount(sshProxy *SSHProxy) int {
	sshProxy.mu.Lock()
	defer sshProxy.mu.Unlock()

	return len(sshProxy.connsMap)
}
