// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/connect"
	"gateway/internal/token"
)

const upstreamAddress = "upstream.internal:22"

var sshConfig = &gatewayconfig.SSHConfig{
	Gateway: gatewayconfig.SSHGatewayConfig{
		Username: "test-user",
	},
}

// Mock SSH connection factory, used for creating downstream and upstream SSH connections.
type mockProxySSHConnFactory struct {
	mock.Mock
}

//revive:disable-next-line:function-result-limit
//nolint:ireturn
func (m *mockProxySSHConnFactory) NewServerConn(c net.Conn, config *ssh.ServerConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	args := m.Called(c, config)

	if args.Get(0) == nil {
		return nil, nil, nil, args.Error(3)
	}

	return args.Get(0).(ssh.Conn), args.Get(1).(<-chan ssh.NewChannel), args.Get(2).(<-chan *ssh.Request), args.Error(3)
}

//revive:disable-next-line:function-result-limit
//nolint:ireturn
func (m *mockProxySSHConnFactory) NewClientConn(c net.Conn, addr string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	args := m.Called(c, addr, config)

	return args.Get(0).(ssh.Conn), args.Get(1).(<-chan ssh.NewChannel), args.Get(2).(<-chan *ssh.Request), args.Error(3)
}

// Mock SSH connection pair factory.
type mockProxySSHConnPairFactory struct {
	mock.Mock
}

//nolint:ireturn
func (m *mockProxySSHConnPairFactory) NewConnPair(logger *zap.Logger, sshCtx *sshContext,
	downstreamConn ssh.Conn, downstreamChannels <-chan ssh.NewChannel, downstreamRequests <-chan *ssh.Request,
	upstreamConn ssh.Conn, upstreamChannels <-chan ssh.NewChannel, upstreamRequests <-chan *ssh.Request,
) ConnPair {
	args := m.Called(logger, sshCtx, downstreamConn, downstreamChannels, downstreamRequests, upstreamConn, upstreamChannels, upstreamRequests)

	return args.Get(0).(ConnPair)
}

// Mock SSH connection pair.
type mockSSHConnPair struct {
	mock.Mock
}

func (m *mockSSHConnPair) ChannelsOpened() int {
	args := m.Called()

	return args.Int(0)
}

func (m *mockSSHConnPair) serve() {
	m.Called()
}

func (m *mockSSHConnPair) close() {
	m.Called()
}

// Mock ProxyConn for testing.
type mockProxyConn struct {
	mock.Mock
	*connect.ProxyConn
}

func (m *mockProxyConn) Close() error {
	args := m.Called()

	return args.Error(0)
}

func (m *mockProxyConn) GetClaims() *token.GATClaims {
	return m.Claims
}

func (m *mockProxyConn) GetID() string {
	return m.ID
}

// Mock ProtocolListener.
type mockProtocolListener struct {
	mock.Mock
	*connect.ProtocolListener
}

func (m *mockProtocolListener) Accept() (net.Conn, error) {
	args := m.Called()

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(net.Conn), args.Error(1)
}

func (m *mockProtocolListener) Close() error {
	args := m.Called()

	return args.Error(0)
}

func (m *mockProtocolListener) Addr() net.Addr {
	args := m.Called()

	return args.Get(0).(net.Addr)
}

// Helper to create a mock ProxyConn for testing.
func newTestProxyConn(claims *token.GATClaims) *mockProxyConn {
	mockProxyNetConn := &mockProxyNetConn{}
	proxyConn := &connect.ProxyConn{
		Conn:    mockProxyNetConn,
		Claims:  claims,
		Address: upstreamAddress,
		ID:      "test-id",
	}
	mockProxyConn := &mockProxyConn{
		ProxyConn: proxyConn,
	}

	return mockProxyConn
}

func TestSSHProxy_Start_AcceptError(t *testing.T) {
	listener := &mockProtocolListener{
		ProtocolListener: &connect.ProtocolListener{},
	}

	config, err := NewConfig(nil, sshConfig, zap.NewNop())
	require.NoError(t, err)

	sshProxy := NewProxy(*config)

	listener.On("Accept").Return(nil, errors.New("error"))

	done := make(chan struct{})

	go func() {
		defer close(done)

		_ = sshProxy.Start(t.Context(), listener)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Start did not complete within timeout")
	}

	listener.AssertExpectations(t)
}

func TestSSHProxy_Start_Shutdown(t *testing.T) {
	listener := &mockProtocolListener{
		ProtocolListener: &connect.ProtocolListener{},
	}

	config, err := NewConfig(nil, sshConfig, zap.NewNop())
	require.NoError(t, err)

	sshProxy := NewProxy(*config)

	listener.On("Accept").Return(nil, nil)

	done := make(chan struct{})

	go func() {
		defer close(done)

		_ = sshProxy.Start(t.Context(), listener)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Start did not complete within timeout")
	}

	listener.AssertExpectations(t)
}

func TestSSHProxy_Start_Success(t *testing.T) {
	listener := &mockProtocolListener{
		ProtocolListener: &connect.ProtocolListener{},
	}

	config, err := NewConfig(nil, sshConfig, zap.NewNop())
	require.NoError(t, err)

	sshProxy := NewProxy(*config)

	// Create a test proxy connection to be served
	claims := &token.GATClaims{}
	testConn := newTestProxyConn(claims)
	closed := make(chan struct{})

	testConn.On("Close").Return(nil).Run(func(_ mock.Arguments) {
		close(closed)
	})

	// Mock listener to return one connection, then an error to exit the loop
	listener.On("Accept").Return(testConn, nil).Once()
	listener.On("Accept").Return(nil, net.ErrClosed).Once()

	// Mock the SSH connection factory to prevent actual SSH handshake
	mockSSHFactory := &mockProxySSHConnFactory{}
	sshProxy.sshConnFactory = mockSSHFactory

	// Mock to return an error immediately so Serve exits quickly
	served := make(chan struct{})

	mockSSHFactory.On("NewServerConn", mock.Anything, mock.Anything).Return(nil, nil, nil, errors.New("mock error")).Run(func(args mock.Arguments) {
		// Validate that the connection used to start the downstream SSH connection is the same one we created
		assert.Equal(t, testConn, args.Get(0))

		served <- struct{}{}
	})

	startFinished := make(chan struct{})

	go func() {
		defer close(startFinished)

		_ = sshProxy.Start(t.Context(), listener)
	}()

	// Wait for the connection to start being served (first Accept())
	select {
	case <-served:
		// Success
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Connection did not start being served within timeout")
	}

	// Wait for Start() to finish after error from second Accept() (listener closed)
	select {
	case <-startFinished:
		// Success
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Start did not complete within timeout")
	}

	select {
	case <-closed:
		// Success
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Close was not called within timeout")
	}

	listener.AssertExpectations(t)
	testConn.AssertExpectations(t)
	mockSSHFactory.AssertExpectations(t)
}

func TestSSHProxy_ServeConn_Success(t *testing.T) {
	mockProxySSHFactory := &mockProxySSHConnFactory{}
	mockProxyDialer := &mockProxyNetDialer{}
	mockProxyConnPairFactory := &mockProxySSHConnPairFactory{}

	config, err := NewConfig(nil, sshConfig, zap.NewNop())
	require.NoError(t, err)

	downstreamConfig, err := config.GetDownstreamConfig(t.Context())
	require.NoError(t, err)

	sshProxy := NewProxy(*config)
	sshProxy.downstreamConfig = downstreamConfig

	// Set mock dependencies for testing
	sshProxy.sshConnFactory = mockProxySSHFactory
	sshProxy.netDialer = mockProxyDialer
	sshProxy.connPairFactory = mockProxyConnPairFactory

	// Create a test proxy connection to be served
	claims := &token.GATClaims{}
	testConn := newTestProxyConn(claims)

	// Mock NewServerConn to return a new downstream SSH connection
	downstreamSSHConn := &mockSSHConn{}
	downstreamSSHConn.On("SessionID").Return([]byte("test-session-id"))
	downstreamSSHConn.On("ClientVersion").Return([]byte("SSH-2.0-test"))

	downstreamChannels := make(chan ssh.NewChannel, 1)
	downstreamRequests := make(chan *ssh.Request, 1)
	mockProxySSHFactory.On("NewServerConn", testConn, downstreamConfig).Return(
		downstreamSSHConn,
		(<-chan ssh.NewChannel)(downstreamChannels),
		(<-chan *ssh.Request)(downstreamRequests),
		nil,
	)

	// Mock successful upstream TCP connection
	upstreamConn := &mockProxyNetConn{}
	mockProxyDialer.On("DialTimeout", "tcp", upstreamAddress, upstreamConnTimeout).Return(
		upstreamConn,
		nil,
	)

	// Mock successful upstream SSH connection
	upstreamSSHConn := &mockSSHConn{}
	upstreamSSHConn.On("ServerVersion").Return([]byte("SSH-2.0-OpenSSH_9.6"))

	upstreamChannels := make(chan ssh.NewChannel, 1)
	upstreamRequests := make(chan *ssh.Request, 1)
	mockProxySSHFactory.On("NewClientConn", upstreamConn, upstreamAddress, mock.AnythingOfType("*ssh.ClientConfig")).Return(
		upstreamSSHConn,
		(<-chan ssh.NewChannel)(upstreamChannels),
		(<-chan *ssh.Request)(upstreamRequests),
		nil,
	)

	// Create mock SSH connection pair
	mockProxyConnPair := &mockSSHConnPair{}

	mockProxyConnPairFactory.On("NewConnPair",
		mock.AnythingOfType("*zap.Logger"),
		mock.AnythingOfType("*sshhandler.sshContext"),
		downstreamSSHConn,
		(<-chan ssh.NewChannel)(downstreamChannels),
		(<-chan *ssh.Request)(downstreamRequests),
		upstreamSSHConn,
		(<-chan ssh.NewChannel)(upstreamChannels),
		(<-chan *ssh.Request)(upstreamRequests),
	).Return(mockProxyConnPair)

	serveDone := make(chan struct{})

	mockProxyConnPair.On("serve").Run(func(_ mock.Arguments) {
		// Return after some delay to simulate a real serve
		time.Sleep(100 * time.Millisecond)
	}).Return()
	mockProxyConnPair.On("ChannelsOpened").Return(0)

	// Call serve - this should succeed and create the mocked SSHConnPair from above
	go func() {
		err := sshProxy.serveConn(t.Context(), testConn)
		assert.NoError(t, err)

		close(serveDone)
	}()

	// Wait for the mocked serve to complete
	<-serveDone

	// Verify that the SSH connection pair was removed from the connection map and it's now empty
	assert.NotContains(t, sshProxy.connsMap, mockProxyConnPair)
	assert.Empty(t, sshProxy.connsMap)

	// Verify all mocks were called as expected
	mockProxySSHFactory.AssertExpectations(t)
	mockProxyDialer.AssertExpectations(t)
	mockProxyConnPairFactory.AssertExpectations(t)
	mockProxyConnPair.AssertExpectations(t)
	testConn.AssertExpectations(t)
}

func TestSSHProxy_ServeConn_DownstreamHandshakeFailure(t *testing.T) {
	mockProxySSHFactory := &mockProxySSHConnFactory{}
	mockProxyDialer := &mockProxyNetDialer{}
	mockProxyConnPairFactory := &mockProxySSHConnPairFactory{}

	config, err := NewConfig(nil, sshConfig, zap.NewNop())
	require.NoError(t, err)

	downstreamConfig, err := config.GetDownstreamConfig(t.Context())
	require.NoError(t, err)

	sshProxy := NewProxy(*config)
	sshProxy.downstreamConfig = downstreamConfig

	// Set mock dependencies for testing
	sshProxy.sshConnFactory = mockProxySSHFactory
	sshProxy.netDialer = mockProxyDialer
	sshProxy.connPairFactory = mockProxyConnPairFactory

	// Create test proxy connection
	claims := &token.GATClaims{}
	testConn := newTestProxyConn(claims)

	// Mock NewServerConn to return an error (handshake failure)
	mockProxySSHFactory.On("NewServerConn", testConn, downstreamConfig).Return(
		(*mockSSHConn)(nil),
		(<-chan ssh.NewChannel)(nil),
		(<-chan *ssh.Request)(nil),
		assert.AnError,
	)

	// Ensure that testConn is closed when serve returns due to error
	testConn.On("Close").Return(nil)

	// Call serve and expect it to fail
	err = sshProxy.serveConn(t.Context(), testConn)

	require.Error(t, err)
	mockProxySSHFactory.AssertExpectations(t)
	testConn.AssertExpectations(t)
	assert.Empty(t, sshProxy.connsMap)

	// NetDialer and ConnPairFactory should not be called since downstream handshake failed
	mockProxyDialer.AssertNotCalled(t, "DialTimeout")
	mockProxyConnPairFactory.AssertNotCalled(t, "NewConnPair")
}

func TestSSHProxy_ServeConn_UpstreamConnectionFailure(t *testing.T) {
	mockProxySSHFactory := &mockProxySSHConnFactory{}
	mockProxyDialer := &mockProxyNetDialer{}
	mockProxyConnPairFactory := &mockProxySSHConnPairFactory{}

	config, err := NewConfig(nil, sshConfig, zap.NewNop())
	require.NoError(t, err)

	downstreamConfig, err := config.GetDownstreamConfig(t.Context())
	require.NoError(t, err)

	sshProxy := NewProxy(*config)
	sshProxy.downstreamConfig = downstreamConfig

	// Set mock dependencies for testing
	sshProxy.sshConnFactory = mockProxySSHFactory
	sshProxy.netDialer = mockProxyDialer
	sshProxy.connPairFactory = mockProxyConnPairFactory

	// Create test proxy connection
	claims := &token.GATClaims{}
	testConn := newTestProxyConn(claims)

	// Mock successful downstream handshake
	downstreamSSHConn := &mockSSHConn{}
	downstreamSSHConn.On("SessionID").Return([]byte("test-session-id"))
	downstreamSSHConn.On("ClientVersion").Return([]byte("SSH-2.0-test"))

	downstreamChannels := make(chan ssh.NewChannel)
	downstreamRequests := make(chan *ssh.Request)
	mockProxySSHFactory.On("NewServerConn", testConn, downstreamConfig).Return(
		downstreamSSHConn,
		(<-chan ssh.NewChannel)(downstreamChannels),
		(<-chan *ssh.Request)(downstreamRequests),
		nil,
	)

	// Mock upstream connection failure
	upstreamConn := &mockProxyNetConn{}
	mockProxyDialer.On("DialTimeout", "tcp", upstreamAddress, upstreamConnTimeout).Return(
		upstreamConn,
		assert.AnError,
	)

	// Simulate real SSH mux behavior: closing the connection closes the channel stream
	downstreamSSHConn.On("Close").Run(func(_ mock.Arguments) {
		close(downstreamChannels)
	}).Return(nil)

	// Call serve and expect it to fail
	err = sshProxy.serveConn(t.Context(), testConn)

	require.Error(t, err)
	mockProxySSHFactory.AssertExpectations(t)
	mockProxyDialer.AssertExpectations(t)
	downstreamSSHConn.AssertExpectations(t)
	assert.Empty(t, sshProxy.connsMap)

	// ConnPairFactory should not be called since upstream connection failed
	mockProxyConnPairFactory.AssertNotCalled(t, "NewConnPair")
}

func TestSSHProxy_ServeConn_UpstreamSSHHandshakeFailure(t *testing.T) {
	mockProxySSHFactory := &mockProxySSHConnFactory{}
	mockProxyDialer := &mockProxyNetDialer{}
	mockProxyConnPairFactory := &mockProxySSHConnPairFactory{}

	config, err := NewConfig(nil, sshConfig, zap.NewNop())
	require.NoError(t, err)

	downstreamConfig, err := config.GetDownstreamConfig(t.Context())
	require.NoError(t, err)

	sshProxy := NewProxy(*config)
	sshProxy.downstreamConfig = downstreamConfig

	// Set mock dependencies for testing
	sshProxy.sshConnFactory = mockProxySSHFactory
	sshProxy.netDialer = mockProxyDialer
	sshProxy.connPairFactory = mockProxyConnPairFactory

	// Create test proxy connection
	claims := &token.GATClaims{}
	testConn := newTestProxyConn(claims)

	// Mock successful downstream handshake
	downstreamSSHConn := &mockSSHConn{}
	downstreamSSHConn.On("SessionID").Return([]byte("test-session-id"))
	downstreamSSHConn.On("ClientVersion").Return([]byte("SSH-2.0-test"))

	downstreamChannels := make(chan ssh.NewChannel)
	downstreamRequests := make(chan *ssh.Request)

	mockProxySSHFactory.On("NewServerConn", testConn, downstreamConfig).Return(
		downstreamSSHConn,
		(<-chan ssh.NewChannel)(downstreamChannels),
		(<-chan *ssh.Request)(downstreamRequests),
		nil,
	)

	// Mock successful upstream TCP connection
	upstreamConn := &mockProxyNetConn{}
	mockProxyDialer.On("DialTimeout", "tcp", upstreamAddress, upstreamConnTimeout).Return(
		upstreamConn,
		nil,
	)

	// Mock upstream SSH handshake failure
	mockProxySSHFactory.On("NewClientConn", upstreamConn, upstreamAddress, mock.AnythingOfType("*ssh.ClientConfig")).Return(
		(*mockSSHConn)(nil),
		(<-chan ssh.NewChannel)(nil),
		(<-chan *ssh.Request)(nil),
		assert.AnError,
	)

	// Simulate real SSH mux behavior: closing the connection closes the channel stream
	downstreamSSHConn.On("Close").Run(func(_ mock.Arguments) {
		close(downstreamChannels)
	}).Return(nil)
	// Ensure upstream connection is closed
	upstreamConn.On("Close").Return(nil)

	// Call serve and expect it to fail
	err = sshProxy.serveConn(t.Context(), testConn)

	require.Error(t, err)
	mockProxySSHFactory.AssertExpectations(t)
	mockProxyDialer.AssertExpectations(t)
	downstreamSSHConn.AssertExpectations(t)
	upstreamConn.AssertExpectations(t)
	testConn.AssertExpectations(t)
	assert.Empty(t, sshProxy.connsMap)

	// ConnPairFactory should not be called since upstream SSH handshake failed
	mockProxyConnPairFactory.AssertNotCalled(t, "NewConnPair")
}

func TestSSHProxy_Shutdown_WithActiveConnection(t *testing.T) {
	mockProxySSHFactory := &mockProxySSHConnFactory{}
	mockProxyDialer := &mockProxyNetDialer{}
	mockProxyConnPairFactory := &mockProxySSHConnPairFactory{}

	config, err := NewConfig(nil, sshConfig, zap.NewNop())
	require.NoError(t, err)

	downstreamConfig, err := config.GetDownstreamConfig(t.Context())
	require.NoError(t, err)

	sshProxy := NewProxy(*config)
	sshProxy.downstreamConfig = downstreamConfig

	// Set mock dependencies for testing
	sshProxy.sshConnFactory = mockProxySSHFactory
	sshProxy.netDialer = mockProxyDialer
	sshProxy.connPairFactory = mockProxyConnPairFactory

	// Create test proxy connection
	claims := &token.GATClaims{}
	testConn := newTestProxyConn(claims)

	// Mock successful downstream handshake
	downstreamSSHConn := &mockSSHConn{}
	downstreamSSHConn.On("SessionID").Return([]byte("test-session-id"))
	downstreamSSHConn.On("ClientVersion").Return([]byte("SSH-2.0-test"))

	downstreamChannels := make(chan ssh.NewChannel, 1)
	downstreamRequests := make(chan *ssh.Request, 1)
	mockProxySSHFactory.On("NewServerConn", testConn, downstreamConfig).Return(
		downstreamSSHConn,
		(<-chan ssh.NewChannel)(downstreamChannels),
		(<-chan *ssh.Request)(downstreamRequests),
		nil,
	)

	// Mock successful upstream TCP connection
	upstreamConn := &mockProxyNetConn{}
	mockProxyDialer.On("DialTimeout", "tcp", upstreamAddress, upstreamConnTimeout).Return(
		upstreamConn,
		nil,
	)

	// Mock successful upstream SSH handshake
	upstreamSSHConn := &mockSSHConn{}
	upstreamSSHConn.On("ServerVersion").Return([]byte("SSH-2.0-OpenSSH_9.6"))

	upstreamChannels := make(chan ssh.NewChannel, 1)
	upstreamRequests := make(chan *ssh.Request, 1)
	mockProxySSHFactory.On("NewClientConn", upstreamConn, upstreamAddress, mock.AnythingOfType("*ssh.ClientConfig")).Return(
		upstreamSSHConn,
		(<-chan ssh.NewChannel)(upstreamChannels),
		(<-chan *ssh.Request)(upstreamRequests),
		nil,
	)

	// Create mock SSH connection pair
	mockProxyConnPair := &mockSSHConnPair{}

	mockProxyConnPairFactory.On("NewConnPair",
		mock.AnythingOfType("*zap.Logger"),
		mock.AnythingOfType("*sshhandler.sshContext"),
		downstreamSSHConn,
		(<-chan ssh.NewChannel)(downstreamChannels),
		(<-chan *ssh.Request)(downstreamRequests),
		upstreamSSHConn,
		(<-chan ssh.NewChannel)(upstreamChannels),
		(<-chan *ssh.Request)(upstreamRequests),
	).Return(mockProxyConnPair)

	// Mock the serve method to block until Close is called
	serveStarted := make(chan struct{})
	closeReceived := make(chan struct{})

	mockProxyConnPair.On("serve").Run(func(_ mock.Arguments) {
		close(serveStarted)
		<-closeReceived // Block until Close is called
	}).Return()
	mockProxyConnPair.On("ChannelsOpened").Return(0)

	// Mock Close to signal that shutdown was called
	mockProxyConnPair.On("close").Run(func(_ mock.Arguments) {
		close(closeReceived)
	}).Return(nil)

	// Start serving the connection in a goroutine
	serveDone := make(chan error, 1)

	go func() {
		serveDone <- sshProxy.serveConn(t.Context(), testConn)
	}()

	// Wait for serve to start and connection to be added
	<-serveStarted

	// Verify downstream connection pair was added to the map
	sshProxy.mu.Lock()
	assert.Contains(t, sshProxy.connsMap, mockProxyConnPair)
	sshProxy.mu.Unlock()

	// Call Shutdown() while the connection is active
	sshProxy.Shutdown(t.Context())

	// Verify shutdown state
	assert.True(t, sshProxy.shuttingDown, "Proxy should be in shutting down state")

	// Wait for serve to complete (should finish due to shutdown)
	select {
	case err := <-serveDone:
		// serve() should complete (may return error or nil depending on timing)
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		t.Fatal("serve() should have completed after shutdown")
	}

	// Verify connections map is empty after shutdown
	sshProxy.mu.Lock()
	finalConnCount := len(sshProxy.connsMap)
	sshProxy.mu.Unlock()
	assert.Equal(t, 0, finalConnCount, "All connections should be removed after shutdown")

	mockProxySSHFactory.AssertExpectations(t)
	mockProxyDialer.AssertExpectations(t)
	mockProxyConnPairFactory.AssertExpectations(t)
	mockProxyConnPair.AssertExpectations(t)
}
