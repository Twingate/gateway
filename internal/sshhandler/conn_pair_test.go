// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/ssh"
)

var testSSHContext = &sshContext{
	id:            "test-session-id",
	username:      "testuser",
	clientVersion: "SSH-2.0-test",
	serverVersion: "SSH-2.0-upstream",
}

// newSSHConnEnds establishes a real SSH connection over loopback TCP and returns its client and
// server ends. The server accepts any client (NoClientAuth) with a generated host key; the client
// does not verify the host key.
func newSSHConnEnds(t *testing.T) (client, server sshConn) {
	t.Helper()

	clientConn, serverConn := newLoopbackConnEnds(t)

	hostSigner, _, err := keyConfig{}.Generate(rand.Reader)
	require.NoError(t, err)

	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(hostSigner)

	type serverResult struct {
		conn sshConn
		err  error
	}

	serverDone := make(chan serverResult, 1)

	// Both ends must handshake concurrently; running NewServerConn before NewClientConn deadlocks.
	go func() {
		serverSSHConn, channels, requests, err := ssh.NewServerConn(serverConn, serverConfig)
		serverDone <- serverResult{conn: sshConn{conn: serverSSHConn, newChannels: channels, requests: requests}, err: err}
	}()

	clientConfig := &ssh.ClientConfig{
		User:            "client",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	clientSSHConn, clientChannels, clientRequests, err := ssh.NewClientConn(clientConn, clientConn.RemoteAddr().String(), clientConfig)
	require.NoError(t, err)

	serverRes := <-serverDone
	require.NoError(t, serverRes.err)

	t.Cleanup(func() {
		_ = clientSSHConn.Close()
		_ = serverRes.conn.conn.Close()
	})

	return sshConn{conn: clientSSHConn, newChannels: clientChannels, requests: clientRequests}, serverRes.conn
}

// newServingConnPair wires two real SSH connections into an SSHConnPair and starts serving. The
// gateway holds the downstream server end and the upstream client end (matching production, where
// the gateway is the SSH server to the client and the SSH client to the upstream); the returned
// ends are the ones the test drives.
func newServingConnPair(t *testing.T) (downstreamClient, upstreamServer sshConn, connPair *SSHConnPair) {
	t.Helper()

	downstreamClient, downstreamServer := newSSHConnEnds(t)
	upstreamClient, upstreamServer := newSSHConnEnds(t)

	connPair = NewSSHConnPair(zap.NewNop(), testSSHContext, downstreamServer, upstreamClient)

	go connPair.serve()

	return downstreamClient, upstreamServer, connPair
}

// assertConnClosed fails unless conn's Wait() returns within a short timeout.
func assertConnClosed(t *testing.T, conn ssh.Conn, label string) {
	t.Helper()

	done := make(chan struct{})

	go func() {
		_ = conn.Wait()

		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s connection was not closed", label)
	}
}

func TestSSHConnPair_serve_ForwardsChannels(t *testing.T) {
	// Each direction forwards a channel type allowed for it (direct-tcpip is client→server;
	// forwarded-tcpip is server→client), proving both forwardChannels goroutines are wired.
	tests := []struct {
		name         string
		channelType  string
		fromUpstream bool
	}{
		{name: "downstream to upstream", channelType: "direct-tcpip", fromUpstream: false},
		{name: "upstream to downstream", channelType: "forwarded-tcpip", fromUpstream: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			downstreamClient, upstreamServer, connPair := newServingConnPair(t)

			go ssh.DiscardRequests(downstreamClient.requests)
			go ssh.DiscardRequests(upstreamServer.requests)

			opener, accepter := downstreamClient, upstreamServer
			if tt.fromUpstream {
				opener, accepter = upstreamServer, downstreamClient
			}

			extraData := []byte("origin-host-data")

			type forwardedChannel struct {
				channelType string
				extraData   []byte
				channel     ssh.Channel
			}

			// Accept the forwarded channel on the far end concurrently: the opener's OpenChannel
			// cannot return until the gateway opens (and the far end accepts) the target.
			forwardedCh := make(chan forwardedChannel, 1)

			go func() {
				newChannel := <-accepter.newChannels

				channel, requests, err := newChannel.Accept()
				if err != nil {
					return
				}

				go ssh.DiscardRequests(requests)

				forwardedCh <- forwardedChannel{newChannel.ChannelType(), newChannel.ExtraData(), channel}
			}()

			openedChannel, openedRequests, err := opener.conn.OpenChannel(tt.channelType, extraData)
			require.NoError(t, err)

			go ssh.DiscardRequests(openedRequests)

			var forwarded forwardedChannel

			select {
			case forwarded = <-forwardedCh:
			case <-time.After(2 * time.Second):
				t.Fatal("channel was not forwarded")
			}

			// The forwarded channel preserves the original type and ExtraData.
			assert.Equal(t, tt.channelType, forwarded.channelType)
			assert.Equal(t, extraData, forwarded.extraData)

			// Round-trip a byte each way to prove the served channel pair forwards data bidirectionally.
			buf := make([]byte, 1)

			_, err = openedChannel.Write([]byte("x"))
			require.NoError(t, err)
			_, err = io.ReadFull(forwarded.channel, buf)
			require.NoError(t, err)
			assert.Equal(t, []byte("x"), buf)

			_, err = forwarded.channel.Write([]byte("y"))
			require.NoError(t, err)
			_, err = io.ReadFull(openedChannel, buf)
			require.NoError(t, err)
			assert.Equal(t, []byte("y"), buf)

			assert.Equal(t, 1, connPair.ChannelsOpened())
		})
	}
}

func TestSSHConnPair_serve_ForwardsGlobalRequests(t *testing.T) {
	// keepalive@openssh.com is allowed in both directions, so serve must forward it each way,
	// proving both forwardGlobalRequests goroutines are wired.
	tests := []struct {
		name         string
		fromUpstream bool
	}{
		{name: "downstream to upstream", fromUpstream: false},
		{name: "upstream to downstream", fromUpstream: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			downstreamClient, upstreamServer, _ := newServingConnPair(t)

			sender, receiver := downstreamClient, upstreamServer
			if tt.fromUpstream {
				sender, receiver = upstreamServer, downstreamClient
			}

			go ssh.DiscardRequests(sender.requests)

			received := make(chan string, 1)

			go func() {
				for req := range receiver.requests {
					received <- req.Type

					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				}
			}()

			ok, _, err := sender.conn.SendRequest("keepalive@openssh.com", true, []byte("ping"))
			require.NoError(t, err)
			assert.True(t, ok)

			select {
			case reqType := <-received:
				assert.Equal(t, "keepalive@openssh.com", reqType)
			case <-time.After(2 * time.Second):
				t.Fatal("request was not forwarded")
			}
		})
	}
}

func TestSSHConnPair_serve_CrossClose(t *testing.T) {
	// Closing either side must tear down the other; each direction is a separate serve() goroutine.
	t.Run("downstream close closes upstream", func(t *testing.T) {
		downstreamClient, upstreamServer, _ := newServingConnPair(t)

		go ssh.DiscardRequests(downstreamClient.requests)
		go ssh.DiscardRequests(upstreamServer.requests)

		require.NoError(t, downstreamClient.conn.Close())

		assertConnClosed(t, upstreamServer.conn, "upstream")
	})

	t.Run("upstream close closes downstream", func(t *testing.T) {
		downstreamClient, upstreamServer, _ := newServingConnPair(t)

		go ssh.DiscardRequests(downstreamClient.requests)
		go ssh.DiscardRequests(upstreamServer.requests)

		require.NoError(t, upstreamServer.conn.Close())

		assertConnClosed(t, downstreamClient.conn, "downstream")
	})
}

func TestSSHConnPair_forwardChannels_RejectsDisallowedType(t *testing.T) {
	downstreamClient, upstreamServer, _ := newServingConnPair(t)

	go ssh.DiscardRequests(downstreamClient.requests)
	go ssh.DiscardRequests(upstreamServer.requests)

	// Surface any channel forwarded to the downstream client so we can assert it never happens.
	downstreamGotChannel := make(chan struct{}, 1)

	go func() {
		for newChannel := range downstreamClient.newChannels {
			downstreamGotChannel <- struct{}{}

			_ = newChannel.Reject(ssh.ConnectionFailed, "no")
		}
	}()

	// "session" from upstream is in disallowedUpstreamChannelTypes and must be rejected with
	// Prohibited rather than forwarded.
	_, _, err := upstreamServer.conn.OpenChannel("session", nil)
	require.Error(t, err)

	var openErr *ssh.OpenChannelError
	require.ErrorAs(t, err, &openErr)
	assert.Equal(t, ssh.Prohibited, openErr.Reason)

	select {
	case <-downstreamGotChannel:
		t.Fatal("disallowed channel was forwarded to downstream")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSSHConnPair_forwardChannels_RejectsOnTargetOpenFailure(t *testing.T) {
	downstreamClient, upstreamServer, _ := newServingConnPair(t)

	go ssh.DiscardRequests(downstreamClient.requests)
	go ssh.DiscardRequests(upstreamServer.requests)

	// The upstream rejects every channel the gateway tries to open (with a distinct reason), so the
	// gateway's target-open fails and it must reject the source with ConnectionFailed.
	go func() {
		for newChannel := range upstreamServer.newChannels {
			_ = newChannel.Reject(ssh.Prohibited, "upstream refuses")
		}
	}()

	_, _, err := downstreamClient.conn.OpenChannel("direct-tcpip", nil)
	require.Error(t, err)

	var openErr *ssh.OpenChannelError
	require.ErrorAs(t, err, &openErr)
	assert.Equal(t, ssh.ConnectionFailed, openErr.Reason)
}

func TestSSHConnPair_forwardGlobalRequests_BlocksDenied(t *testing.T) {
	downstreamClient, upstreamServer, _ := newServingConnPair(t)

	go ssh.DiscardRequests(upstreamServer.requests)

	received := make(chan string, 1)

	go func() {
		for req := range downstreamClient.requests {
			received <- req.Type

			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
	}()

	// tcpip-forward is a client→server request; from upstream it is in the denylist and must be
	// dropped (replied false), never reaching downstream.
	ok, _, err := upstreamServer.conn.SendRequest("tcpip-forward", true, nil)
	require.NoError(t, err)
	assert.False(t, ok)

	select {
	case <-received:
		t.Fatal("denied request was forwarded to downstream")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSSHConnPair_forwardGlobalRequests_SendError(t *testing.T) {
	// A real (but closed) destination conn makes SendRequest fail, exercising the forward-error path.
	_, dst := newSSHConnEnds(t)

	go ssh.DiscardRequests(dst.requests)

	require.NoError(t, dst.conn.Close())

	core, logs := observer.New(zap.DebugLevel)
	connPair := NewSSHConnPair(zap.New(core), testSSHContext, sshConn{}, sshConn{})

	// An allowed request with WantReply=false is forwarded (and fails), and needs no reply, so the
	// error path is reached without a live source channel.
	requests := make(chan *ssh.Request, 1)
	requests <- &ssh.Request{Type: "keepalive@openssh.com", WantReply: false}

	close(requests)

	connPair.forwardGlobalRequests(requests, dst.conn, nil, labelDownstream, labelUpstream)

	assert.NotEmpty(t, logs.FilterMessage("Failed to forward global request").All(),
		"a failed forward should be logged")
}

func TestSSHConnPair_close(t *testing.T) {
	downstreamClient, downstreamServer := newSSHConnEnds(t)
	upstreamClient, upstreamServer := newSSHConnEnds(t)

	go ssh.DiscardRequests(downstreamClient.requests)
	go ssh.DiscardRequests(upstreamServer.requests)

	connPair := NewSSHConnPair(zap.NewNop(), testSSHContext, downstreamServer, upstreamClient)

	// serve() is intentionally not started, so cross-close cannot mask a missing Close().
	connPair.close()

	assertConnClosed(t, downstreamClient.conn, "downstream")
	assertConnClosed(t, upstreamServer.conn, "upstream")
}

// fakeConn is a minimal ssh.Conn whose Close and Wait are controllable. The embedded nil interface
// panics on any other method, so it is only safe while the code under test touches just these two.
type fakeConn struct {
	ssh.Conn

	closeErr error
	waitCh   chan struct{}
}

func (f *fakeConn) Close() error {
	return f.closeErr
}

func (f *fakeConn) Wait() error {
	<-f.waitCh

	return nil
}

// fakeNewChannel is a minimal ssh.NewChannel whose Accept and Reject outcomes are controllable.
type fakeNewChannel struct {
	channelType string
	acceptErr   error
	rejectErr   error
}

func (f *fakeNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, f.acceptErr
}

func (f *fakeNewChannel) Reject(_ ssh.RejectionReason, _ string) error {
	return f.rejectErr
}

func (f *fakeNewChannel) ChannelType() string {
	return f.channelType
}

func (f *fakeNewChannel) ExtraData() []byte {
	return nil
}

func TestSSHConnPair_close_LogsCloseErrors(t *testing.T) {
	// Close() returning a non-net.ErrClosed error on each side must be logged.
	core, logs := observer.New(zap.DebugLevel)
	connPair := NewSSHConnPair(
		zap.New(core),
		testSSHContext,
		sshConn{conn: &fakeConn{closeErr: errors.New("downstream boom")}},
		sshConn{conn: &fakeConn{closeErr: errors.New("upstream boom")}},
	)

	connPair.close()

	assert.NotEmpty(t, logs.FilterMessage("Failed to close downstream connection").All())
	assert.NotEmpty(t, logs.FilterMessage("Failed to close upstream connection").All())
}

func TestSSHConnPair_close_IgnoresErrClosed(t *testing.T) {
	// net.ErrClosed is expected on an already-closed conn and must not be logged.
	core, logs := observer.New(zap.DebugLevel)
	connPair := NewSSHConnPair(
		zap.New(core),
		testSSHContext,
		sshConn{conn: &fakeConn{closeErr: net.ErrClosed}},
		sshConn{conn: &fakeConn{closeErr: net.ErrClosed}},
	)

	connPair.close()

	assert.Empty(t, logs.All())
}

func TestSSHConnPair_serve_LogsCrossCloseErrors(t *testing.T) {
	// When one side's Wait returns, serve() closes the other; a non-net.ErrClosed error there is
	// logged at Debug. Empty closed request/channel streams let the forward goroutines exit so
	// serve() returns.
	core, logs := observer.New(zap.DebugLevel)

	emptyRequests := make(chan *ssh.Request)
	close(emptyRequests)

	emptyChannels := make(chan ssh.NewChannel)
	close(emptyChannels)

	downstreamWait := make(chan struct{})
	upstreamWait := make(chan struct{})

	connPair := NewSSHConnPair(
		zap.New(core),
		testSSHContext,
		sshConn{
			conn:        &fakeConn{closeErr: errors.New("downstream boom"), waitCh: downstreamWait},
			newChannels: emptyChannels,
			requests:    emptyRequests,
		},
		sshConn{
			conn:        &fakeConn{closeErr: errors.New("upstream boom"), waitCh: upstreamWait},
			newChannels: emptyChannels,
			requests:    emptyRequests,
		},
	)

	close(downstreamWait)
	close(upstreamWait)

	connPair.serve()

	assert.NotEmpty(t, logs.FilterMessage("Failed to close upstream connection").All())
	assert.NotEmpty(t, logs.FilterMessage("Failed to close downstream connection").All())
}

func TestSSHConnPair_forwardChannels_RejectError(t *testing.T) {
	// When Reject() itself fails, the failure must be logged. Two reject sites: a disallowed channel
	// type, and an allowed type whose target-open fails first.
	tests := []struct {
		name        string
		channelType string
		closeTarget bool
		wantLog     string
	}{
		{
			name:        "disallowed type",
			channelType: "x11", // in disallowedDownstreamChannelTypes
			wantLog:     "Failed to reject channel",
		},
		{
			name:        "target open failure",
			channelType: "direct-tcpip", // allowed downstream, but target-open fails
			closeTarget: true,
			wantLog:     "Failed to reject source channel",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)

			_, target := newSSHConnEnds(t)
			go ssh.DiscardRequests(target.requests)

			if tt.closeTarget {
				// A closed target conn makes the gateway's OpenChannel fail.
				require.NoError(t, target.conn.Close())
			}

			connPair := NewSSHConnPair(zap.New(core), testSSHContext, sshConn{}, sshConn{})

			channels := make(chan ssh.NewChannel, 1)
			channels <- &fakeNewChannel{channelType: tt.channelType, rejectErr: errors.New("reject failed")}

			close(channels)

			connPair.forwardChannels(channels, target.conn, disallowedDownstreamChannelTypes, labelDownstream, labelUpstream)

			assert.NotEmpty(t, logs.FilterMessage(tt.wantLog).All())
		})
	}
}

func TestSSHConnPair_forwardChannels_AcceptError(t *testing.T) {
	// After the target channel opens, a failed Accept() of the source channel must be logged and the
	// already-opened target channel cleaned up (not counted as opened).
	core, logs := observer.New(zap.DebugLevel)

	// Both ends of one connection: the gateway opens the target on upstreamClient, the far end
	// (upstreamServer) accepts it so OpenChannel succeeds and the code reaches the source Accept().
	upstreamClient, upstreamServer := newSSHConnEnds(t)
	go ssh.DiscardRequests(upstreamClient.requests)
	go ssh.DiscardRequests(upstreamServer.requests)

	go func() {
		for newChannel := range upstreamServer.newChannels {
			channel, requests, err := newChannel.Accept()
			if err != nil {
				return
			}

			go ssh.DiscardRequests(requests)
			go func() { _, _ = io.Copy(io.Discard, channel) }()
		}
	}()

	connPair := NewSSHConnPair(zap.New(core), testSSHContext, sshConn{}, sshConn{})

	channels := make(chan ssh.NewChannel, 1)
	channels <- &fakeNewChannel{channelType: "direct-tcpip", acceptErr: errors.New("accept failed")}

	close(channels)

	connPair.forwardChannels(channels, upstreamClient.conn, disallowedDownstreamChannelTypes, labelDownstream, labelUpstream)

	assert.NotEmpty(t, logs.FilterMessage("Failed to accept source channel").All())
	assert.Zero(t, connPair.ChannelsOpened(), "a failed accept must not count as an opened channel")
}

func TestReplyToGlobalRequest_ReplyError(t *testing.T) {
	// Replying on a request whose connection has been torn down must log the failure.
	client, server := newSSHConnEnds(t)

	received := make(chan *ssh.Request, 1)

	go func() {
		for req := range server.requests {
			received <- req
		}
	}()

	go func() {
		// WantReply=true so replyToGlobalRequest attempts a reply.
		_, _, _ = client.conn.SendRequest("keepalive@openssh.com", true, nil)
	}()

	var req *ssh.Request

	select {
	case req = <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("global request was not received")
	}

	// Tear down both ends so the reply cannot be written back.
	require.NoError(t, client.conn.Close())
	require.NoError(t, server.conn.Close())

	core, logs := observer.New(zap.DebugLevel)
	replyToGlobalRequest(req, true, nil, zap.New(core))

	assert.NotEmpty(t, logs.FilterMessage("Failed to reply to global request").All())
}
