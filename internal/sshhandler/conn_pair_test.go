// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/ssh"
)

func TestConnPair_ForwardsChannels(t *testing.T) {
	// The table proves per-direction open/accept forwarding preserves the channel type and extra
	// data and spawns exactly one channel pair.
	tests := []struct {
		name         string
		channelType  string
		fromUpstream bool
	}{
		{name: "downstream to upstream", channelType: "direct-tcpip"},
		{name: "upstream to downstream", channelType: "forwarded-tcpip", fromUpstream: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conns := newProxyConns(t)
			done := conns.serve(t)

			opener, acceptor := conns.client, conns.server
			if tt.fromUpstream {
				opener, acceptor = conns.server, conns.client
			}

			openChannel(t, opener, acceptor, tt.channelType, []byte("original-extra-data"))

			// The count is only settled once serve() has returned.
			conns.close(t, done)
			assert.Equal(t, 1, conns.pair.ChannelsOpened())
		})
	}
}

func TestConnPair_LogsChannelForwardingDetails(t *testing.T) {
	// The destination and originator in direct-tcpip / forwarded-tcpip open payloads
	// (RFC 4254 §7.2) must reach the audit log; a malformed payload is logged and the channel
	// still forwarded opaquely.
	openPayload := ssh.Marshal(&tcpipChannelOpen{
		DestAddr: "internal.example.com",
		DestPort: 5432,
		OrigAddr: "192.0.2.10",
		OrigPort: 43210,
	})

	wantChannelFields := map[string]any{
		"destination_address": "internal.example.com",
		"destination_port":    uint32(5432),
		"originator_address":  "192.0.2.10",
		"originator_port":     uint32(43210),
	}

	tests := []struct {
		name         string
		channelType  string
		fromUpstream bool
		extraData    []byte
		// wantFields are the forwarding details the channel log must carry; nil expects a parse
		// failure instead.
		wantFields map[string]any
	}{
		{
			name:        "direct-tcpip from downstream",
			channelType: channelTypeDirectTCPIP,
			extraData:   openPayload,
			wantFields:  wantChannelFields,
		},
		{
			name:         "forwarded-tcpip from upstream",
			channelType:  channelTypeForwardedTCPIP,
			fromUpstream: true,
			extraData:    openPayload,
			wantFields:   wantChannelFields,
		},
		{
			name:        "malformed payload is logged and still forwarded",
			channelType: channelTypeDirectTCPIP,
			extraData:   []byte("not-a-tcpip-payload"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			conns := newProxyConnsWithLogger(t, zap.New(core))
			done := conns.serve(t)

			opener, acceptor := conns.client, conns.server
			if tt.fromUpstream {
				opener, acceptor = conns.server, conns.client
			}

			openChannel(t, opener, acceptor, tt.channelType, tt.extraData)
			conns.close(t, done)

			channelField, isMap := observedSSHField(t, logs, "SSH channel opened")["channel"].(map[string]any)
			require.True(t, isMap)

			if tt.wantFields == nil {
				assert.NotEmpty(t, logs.FilterMessage("Failed to parse channel open").All())
				assert.NotContains(t, channelField, "destination_address")
			}

			assert.Subset(t, channelField, tt.wantFields)
		})
	}
}

func TestConnPair_ConcurrentChannels(t *testing.T) {
	// An open channel must not block new ones: each pair is served on its own goroutine.
	conns := newProxyConns(t)
	done := conns.serve(t)

	firstOpener, firstAcceptor := openChannel(t, conns.client, conns.server, "direct-tcpip", nil)
	secondOpener, secondAcceptor := openChannel(t, conns.client, conns.server, "direct-tcpip", nil)

	_, err := secondOpener.ch.Write([]byte("second"))
	require.NoError(t, err)
	assert.Equal(t, "second", string(readInFull(t, secondAcceptor.ch, len("second"))))

	// The first channel still works after the second one opened and exchanged data.
	_, err = firstOpener.ch.Write([]byte("first"))
	require.NoError(t, err)
	assert.Equal(t, "first", string(readInFull(t, firstAcceptor.ch, len("first"))))

	conns.close(t, done)
	assert.Equal(t, 2, conns.pair.ChannelsOpened())
}

func TestConnPair_ChannelPolicy(t *testing.T) {
	// Every denylisted type per direction must be rejected with Prohibited.
	tests := []struct {
		name            string
		fromUpstream    bool
		disallowedTypes []string
	}{
		{name: "from downstream", disallowedTypes: []string{"x11", "forwarded-tcpip"}},
		{name: "from upstream", fromUpstream: true, disallowedTypes: []string{"session", "direct-tcpip", "x11"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conns := newProxyConns(t)
			done := conns.serve(t)

			opener := conns.client
			if tt.fromUpstream {
				opener = conns.server
			}

			for _, channelType := range tt.disallowedTypes {
				_, _, err := opener.conn.OpenChannel(channelType, nil)

				var openErr *ssh.OpenChannelError

				require.ErrorAs(t, err, &openErr)
				assert.Equal(t, ssh.Prohibited, openErr.Reason, "channel type %q must be rejected", channelType)
			}

			conns.close(t, done)
		})
	}
}

func TestConnPair_TargetOpenChannelFailure(t *testing.T) {
	conns := newProxyConns(t)
	done := conns.serve(t)

	// The upstream server refuses every open with its own reason; the proxy must reject the
	// source with ConnectionFailed, not echo the upstream's reason.
	go func() {
		for newChannel := range conns.server.channels {
			_ = newChannel.Reject(ssh.Prohibited, "upstream refuses")
		}
	}()

	_, _, err := conns.client.conn.OpenChannel("direct-tcpip", nil)

	var openErr *ssh.OpenChannelError

	require.ErrorAs(t, err, &openErr)
	assert.Equal(t, ssh.ConnectionFailed, openErr.Reason)

	conns.close(t, done)
	assert.Zero(t, conns.pair.ChannelsOpened())
}

func TestConnPair_SourceAcceptFailure(t *testing.T) {
	// A source Accept() fails only on a dead transport, which a serving pair cannot produce, so
	// this drives forwardChannels directly with a dead source channel over a live upstream that
	// accepts the forwarded target open.
	proxyUpstream, upstreamServer := sshPipe(t)
	target := acceptChannel(t, upstreamServer)

	core, logs := observer.New(zap.DebugLevel)
	pair := NewSSHConnPair(zap.New(core), testSSHContext, connection{}, *proxyUpstream)
	forwardDeadChannel(t, pair, proxyUpstream.conn, "direct-tcpip")

	// The already-opened target channel is closed again.
	select {
	case targetCh := <-target:
		assertEOF(t, targetCh.ch)
	case <-time.After(testTimeout):
		t.Fatal("target channel was never opened")
	}

	assert.NotEmpty(t, logs.FilterMessage("Failed to accept source channel").All())
	assert.Zero(t, pair.ChannelsOpened(), "a failed accept must not count as an opened channel")
}

func TestConnPair_ForwardsGlobalRequests(t *testing.T) {
	tests := []struct {
		name         string
		fromUpstream bool
		reqType      string
		payload      []byte
		wantReply    bool
		replyOK      bool
		replyPayload []byte
	}{
		{
			name:         "downstream to upstream",
			reqType:      "tcpip-forward",
			payload:      []byte("forward-payload"),
			wantReply:    true,
			replyOK:      true,
			replyPayload: []byte("reply-payload"),
		},
		{
			name:         "upstream to downstream",
			fromUpstream: true,
			reqType:      "keepalive@openssh.com",
			payload:      []byte("ping"),
			wantReply:    true,
			replyOK:      true,
		},
		{
			name:         "failure reply propagated",
			fromUpstream: true,
			reqType:      "keepalive@openssh.com",
			payload:      []byte("ping"),
			wantReply:    true,
			replyOK:      false,
		},
		{
			name:    "forward wantReply=false and return immediately",
			reqType: "no-more-sessions@openssh.com",
			payload: []byte("no-reply"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conns := newProxyConns(t)
			done := conns.serve(t)

			sender, receiver := conns.client, conns.server
			if tt.fromUpstream {
				sender, receiver = conns.server, conns.client
			}

			awaitReply := sendGlobalRequest(sender.conn, tt.reqType, tt.wantReply, tt.payload)

			forwarded := assertSentRequest(t, receiver.requests, tt.reqType)
			assert.Equal(t, tt.wantReply, forwarded.WantReply)
			assert.Equal(t, tt.payload, forwarded.Payload)

			if tt.wantReply {
				require.NoError(t, forwarded.Reply(tt.replyOK, tt.replyPayload))
			}

			// A wantReply=false request expects no reply, so SendRequest returns (false, nil).
			ok, replyPayload, err := awaitReply(t)
			require.NoError(t, err)
			assert.Equal(t, tt.replyOK, ok)
			assert.Equal(t, string(tt.replyPayload), string(replyPayload))

			conns.close(t, done)
		})
	}
}

func TestConnPair_LogsGlobalRequestForwardingDetails(t *testing.T) {
	// The bind address and port in tcpip-forward / cancel-tcpip-forward payloads (RFC 4254 §7.1)
	// must reach the audit log; a malformed payload is logged and the request still forwarded opaquely.
	forwardPayload := ssh.Marshal(&tcpipForwardReq{BindAddr: "0.0.0.0", BindPort: 8080})

	wantRequestFields := map[string]any{
		"bind_address": "0.0.0.0",
		"bind_port":    uint32(8080),
	}

	tests := []struct {
		name    string
		reqType string
		payload []byte
		// replyPayload is what the far end replies with; a tcpip-forward that asked for bind
		// port 0 gets the dynamically allocated port back in it (RFC 4254 §7.1).
		replyPayload []byte
		// wantFields are the forwarding details the request log must carry; nil expects a request
		// parse failure instead.
		wantFields map[string]any
		// wantReplyParseFailure expects the reply payload to fail parsing, logged separately from
		// the request itself.
		wantReplyParseFailure bool
	}{
		{
			name:       "tcpip-forward",
			reqType:    globalRequestTCPIPForward,
			payload:    forwardPayload,
			wantFields: wantRequestFields,
		},
		{
			name:         "tcpip-forward with dynamically allocated port",
			reqType:      globalRequestTCPIPForward,
			payload:      ssh.Marshal(&tcpipForwardReq{BindAddr: "0.0.0.0", BindPort: 0}),
			replyPayload: ssh.Marshal(&tcpipForwardReply{BoundPort: 54321}),
			wantFields: map[string]any{
				"bind_address":   "0.0.0.0",
				"bind_port":      uint32(0),
				"allocated_port": uint32(54321),
			},
		},
		{
			name:       "cancel-tcpip-forward",
			reqType:    globalRequestCancelTCPIPForward,
			payload:    forwardPayload,
			wantFields: wantRequestFields,
		},
		{
			name:    "malformed payload is logged and still forwarded",
			reqType: globalRequestTCPIPForward,
			payload: []byte("garbage"),
		},
		{
			name:                  "malformed reply payload is logged and still forwarded",
			reqType:               globalRequestTCPIPForward,
			payload:               forwardPayload,
			replyPayload:          []byte("garbage"),
			wantFields:            wantRequestFields,
			wantReplyParseFailure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			conns := newProxyConnsWithLogger(t, zap.New(core))
			done := conns.serve(t)

			awaitReply := sendGlobalRequest(conns.client.conn, tt.reqType, true, tt.payload)

			forwarded := assertSentRequest(t, conns.server.requests, tt.reqType)
			require.NoError(t, forwarded.Reply(true, tt.replyPayload))

			ok, _, err := awaitReply(t)
			require.NoError(t, err)
			assert.True(t, ok)

			conns.close(t, done)

			requestField, isMap := observedSSHField(t, logs, "SSH global request")["global_request"].(map[string]any)
			require.True(t, isMap)

			if tt.wantFields == nil {
				assert.NotEmpty(t, logs.FilterMessage("Failed to parse global request").All())
				assert.NotContains(t, requestField, "bind_address")
			}

			if tt.wantReplyParseFailure {
				assert.NotEmpty(t, logs.FilterMessage("Failed to parse global request reply").All())
				assert.NotContains(t, requestField, "allocated_port")
			}

			assert.Subset(t, requestField, tt.wantFields)
			assert.Equal(t, true, requestField["accepted"])
		})
	}
}

func TestConnPair_LogsRejectedGlobalRequestDetails(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	conns := newProxyConnsWithLogger(t, zap.New(core))
	done := conns.serve(t)

	payload := ssh.Marshal(&tcpipForwardReq{BindAddr: "0.0.0.0", BindPort: 8080})
	ok, _, err := sendGlobalRequest(conns.server.conn, globalRequestTCPIPForward, true, payload)(t)
	require.NoError(t, err)
	assert.False(t, ok, "upstream tcpip-forward must be rejected")

	conns.close(t, done)

	requestField, isMap := observedSSHField(t, logs, "SSH global request rejected")["global_request"].(map[string]any)
	require.True(t, isMap)
	assert.Subset(t, requestField, map[string]any{
		"bind_address": "0.0.0.0",
		"bind_port":    uint32(8080),
	})
}

func TestConnPair_GlobalRequestPolicy(t *testing.T) {
	// Every denylisted type per direction must be replied false without reaching the far end (a
	// forwarded request would block for a reply nobody sends and time out instead). Sending the
	// types in turn also proves the loop keeps serving after a denial.
	tests := []struct {
		name            string
		fromUpstream    bool
		disallowedTypes []string
	}{
		{name: "from downstream", disallowedTypes: []string{"hostkeys-00@openssh.com", "hostkeys-prove-00@openssh.com"}},
		{name: "from upstream", fromUpstream: true, disallowedTypes: []string{"tcpip-forward", "cancel-tcpip-forward", "hostkeys-00@openssh.com", "hostkeys-prove-00@openssh.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conns := newProxyConns(t)
			done := conns.serve(t)

			sender := conns.client
			if tt.fromUpstream {
				sender = conns.server
			}

			for _, reqType := range tt.disallowedTypes {
				ok, _, err := sendGlobalRequest(sender.conn, reqType, true, nil)(t)
				require.NoError(t, err)
				assert.False(t, ok, "global request type %q must be rejected", reqType)
			}

			conns.close(t, done)
		})
	}
}

func TestConnPair_GlobalRequestSendError(t *testing.T) {
	// SendRequest fails only on a dead transport, and killing the upstream mid-serve races the
	// cross-close teardown of the downstream side, so this drives forwardGlobalRequests
	// directly: a real pending request from a live source connection, forwarded to a real but
	// already-closed target connection.
	downstreamClient, proxyDownstream := sshPipe(t)
	awaitReply := sendGlobalRequest(downstreamClient.conn, "tcpip-forward", true, []byte("payload"))
	req := assertSentRequest(t, proxyDownstream.requests, "tcpip-forward")

	proxyUpstream, _ := sshPipe(t)
	require.NoError(t, proxyUpstream.conn.Close())

	requests := make(chan *ssh.Request, 1)
	requests <- req

	close(requests)

	core, logs := observer.New(zap.DebugLevel)
	pair := NewSSHConnPair(zap.New(core), testSSHContext, *proxyDownstream, *proxyUpstream)
	pair.forwardGlobalRequests(requests, proxyUpstream.conn, nil, labelDownstream, labelUpstream)

	// The failed forward is logged and the origin gets a failure reply.
	ok, _, err := awaitReply(t)
	require.NoError(t, err)
	assert.False(t, ok, "the origin must get a failure reply when the forward fails")
	assert.NotEmpty(t, logs.FilterMessage("Failed to forward global request").All())
}

func TestConnPair_CrossClose(t *testing.T) {
	// Closing either side must tear down the other and let serve() return, releasing its six
	// watcher/forwarder goroutines.
	tests := []struct {
		name          string
		closeUpstream bool
	}{
		{name: "downstream close tears down upstream"},
		{name: "upstream close tears down downstream", closeUpstream: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conns := newProxyConns(t)
			done := conns.serve(t)

			closing, other := conns.client, conns.server
			if tt.closeUpstream {
				closing, other = conns.server, conns.client
			}

			require.NoError(t, closing.conn.Close())

			assertConnClosed(t, other.conn)
			waitDone(t, done)
		})
	}
}

func TestConnPair_CloseErrors(t *testing.T) {
	tests := []struct {
		name string
		// wantMsg is the log the run must produce; empty asserts nothing is logged.
		wantMsg string
		run     func(t *testing.T, logger *zap.Logger)
	}{
		{
			name:    "logs downstream close error",
			wantMsg: "Failed to close downstream connection",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				_, proxyDownstream := sshPipeWithClose(t, nil, errors.New("close failed"))
				proxyUpstream, _ := sshPipe(t)

				NewSSHConnPair(logger, testSSHContext, *proxyDownstream, *proxyUpstream).close()
			},
		},
		{
			name:    "logs upstream close error",
			wantMsg: "Failed to close upstream connection",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				_, proxyDownstream := sshPipe(t)
				proxyUpstream, _ := sshPipeWithClose(t, errors.New("close failed"), nil)

				NewSSHConnPair(logger, testSSHContext, *proxyDownstream, *proxyUpstream).close()
			},
		},
		{
			name: "ignores ErrClosed on already-closed connections",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				_, proxyDownstream := sshPipe(t)
				proxyUpstream, _ := sshPipe(t)

				require.NoError(t, proxyDownstream.conn.Close())
				require.NoError(t, proxyUpstream.conn.Close())

				NewSSHConnPair(logger, testSSHContext, *proxyDownstream, *proxyUpstream).close()
			},
		},
		{
			name:    "cross-close logs upstream close error",
			wantMsg: "Failed to close upstream connection",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				downstreamClient, proxyDownstream := sshPipe(t)
				proxyUpstream, _ := sshPipeWithClose(t, errors.New("close failed"), nil)

				pair := NewSSHConnPair(logger, testSSHContext, *proxyDownstream, *proxyUpstream)
				done := make(chan struct{})

				go func() {
					pair.serve()
					close(done)
				}()

				// Closing the downstream far end makes serve() cross-close the upstream
				// connection, whose Close() fails.
				require.NoError(t, downstreamClient.conn.Close())
				waitDone(t, done)
			},
		},
		{
			name:    "cross-close logs downstream close error",
			wantMsg: "Failed to close downstream connection",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				_, proxyDownstream := sshPipeWithClose(t, nil, errors.New("close failed"))
				proxyUpstream, upstreamServer := sshPipe(t)

				pair := NewSSHConnPair(logger, testSSHContext, *proxyDownstream, *proxyUpstream)
				done := make(chan struct{})

				go func() {
					pair.serve()
					close(done)
				}()

				// Closing the upstream far end makes serve() cross-close the downstream
				// connection, whose Close() fails.
				require.NoError(t, upstreamServer.conn.Close())
				waitDone(t, done)
			},
		},
		{
			name:    "reject of a disallowed channel on a dead source",
			wantMsg: "Failed to reject channel",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				proxyUpstream, _ := sshPipe(t)
				require.NoError(t, proxyUpstream.conn.Close())

				pair := NewSSHConnPair(logger, testSSHContext, connection{}, *proxyUpstream)
				forwardDeadChannel(t, pair, proxyUpstream.conn, "x11")
			},
		},
		{
			name:    "reject after target open failure on a dead source",
			wantMsg: "Failed to reject source channel",
			run: func(t *testing.T, logger *zap.Logger) {
				t.Helper()

				// The closed target connection fails the open, then the reject of the dead
				// source channel fails too.
				proxyUpstream, _ := sshPipe(t)
				require.NoError(t, proxyUpstream.conn.Close())

				pair := NewSSHConnPair(logger, testSSHContext, connection{}, *proxyUpstream)
				forwardDeadChannel(t, pair, proxyUpstream.conn, "direct-tcpip")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)

			tt.run(t, zap.New(core))

			if tt.wantMsg == "" {
				assert.Empty(t, logs.All(), "an expected close error must not be logged")
			} else {
				assert.NotEmpty(t, logs.FilterMessage(tt.wantMsg).All())
			}
		})
	}
}

// proxyConns is the connection-layer fixture: an SSHConnPair serving between two real SSH
// connections, with the proxy holding the same ends it does in production (the SSH server end
// toward the downstream client, the SSH client end toward the upstream server):
//
//	         downstream conn   +----------------------------------+  upstream conn
//	client <-----------------> | proxyDownstream    proxyUpstream | <-----------------> server
//	                           +-------------- proxy -------------+
//
// The tests drive the far ends (client and server) and assert only there.
type proxyConns struct {
	pair *SSHConnPair

	client *connection
	server *connection
}

// newProxyConns builds a proxyConns fixture over two real SSH connections.
func newProxyConns(t *testing.T) *proxyConns {
	t.Helper()

	return newProxyConnsWithLogger(t, zaptest.NewLogger(t))
}

// newProxyConnsWithLogger is newProxyConns with a caller-supplied logger, for tests asserting
// the pair's log output.
func newProxyConnsWithLogger(t *testing.T, logger *zap.Logger) *proxyConns {
	t.Helper()

	client, proxyDownstream := sshPipe(t)
	proxyUpstream, server := sshPipe(t)

	pair := NewSSHConnPair(logger, testSSHContext, *proxyDownstream, *proxyUpstream)

	return &proxyConns{pair: pair, client: client, server: server}
}

// serve runs the pair's serve() in the background; the returned channel closes when serve returns.
func (p *proxyConns) serve(t *testing.T) <-chan struct{} {
	t.Helper()

	done := make(chan struct{})

	go func() {
		p.pair.serve()
		close(done)
	}()

	return done
}

// close closes both far ends and waits for serve() to return.
func (p *proxyConns) close(t *testing.T, done <-chan struct{}) {
	t.Helper()

	_ = p.client.conn.Close()
	_ = p.server.conn.Close()

	waitDone(t, done)
}

// newDeadChannel opens a channel of the given type from a real SSH client, captures the
// matching ssh.NewChannel at the server end without answering it, and closes the server
// connection, so any later mux send on the returned channel (Accept or Reject) fails.
func newDeadChannel(t *testing.T, channelType string) ssh.NewChannel {
	t.Helper()

	client, server := sshPipe(t)

	// OpenChannel blocks until the channel is answered or the connection dies, so it must run
	// off the test goroutine; the failed result is discarded.
	go func() {
		_, _, _ = client.conn.OpenChannel(channelType, nil)
	}()

	select {
	case newChannel := <-server.channels:
		require.NoError(t, server.conn.Close())

		return newChannel
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for the channel open")

		return nil
	}
}

// forwardDeadChannel drives forwardChannels (downstream direction) with a single dead source
// channel of the given type over targetConn, returning once the one-shot input channel drains.
func forwardDeadChannel(t *testing.T, pair *SSHConnPair, targetConn ssh.Conn, channelType string) {
	t.Helper()

	channels := make(chan ssh.NewChannel, 1)
	channels <- newDeadChannel(t, channelType)

	close(channels)

	pair.forwardChannels(channels, targetConn, disallowedDownstreamChannelTypes, labelDownstream, labelUpstream)
}
