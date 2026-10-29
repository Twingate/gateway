// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gateway/internal/logging"
)

const testTimeout = 5 * time.Second

// testRelay connects a relay to a test client and a test server, each over its own TCP connection:
//
//	client ◀──downstream──▶ relay ◀──upstream──▶ server
type testRelay struct {
	relay      *relay
	client     *pgproto3.Frontend
	clientConn net.Conn
	server     *pgproto3.Backend
	serverConn net.Conn
}

func newTestRelay(t *testing.T, observers ...observer) *testRelay {
	t.Helper()

	pipe := tcpPipe(t)
	clientConn, relayDownstreamConn := pipe()
	relayUpstreamConn, serverConn := pipe()

	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	return &testRelay{
		relay: newRelay(
			logging.NewNop(),
			newDownstreamConn(relayDownstreamConn),
			&pgconn.HijackedConn{
				Conn:     relayUpstreamConn,
				Frontend: pgproto3.NewFrontend(relayUpstreamConn, relayUpstreamConn),
			},
			observers,
		),
		client:     pgproto3.NewFrontend(clientConn, clientConn),
		clientConn: clientConn,
		server:     pgproto3.NewBackend(serverConn, serverConn),
		serverConn: serverConn,
	}
}

// serve runs the relay in the background and stops it on cleanup, so that it never outlives the
// test.
func (r *testRelay) serve(ctx context.Context, t *testing.T) <-chan error {
	t.Helper()

	done := make(chan error, 1)
	stopped := make(chan struct{})

	go func() {
		done <- r.relay.serve(ctx)

		close(stopped)
	}()

	t.Cleanup(func() {
		_ = r.clientConn.Close()
		_ = r.serverConn.Close()

		select {
		case <-stopped:
		case <-time.After(testTimeout):
			t.Error("timed out waiting for the relay to stop")
		}
	})

	return done
}

func (r *testRelay) sendFromClient(t *testing.T, msg pgproto3.FrontendMessage) {
	t.Helper()

	r.client.Send(msg)
	require.NoError(t, r.client.Flush())
}

func (r *testRelay) sendFromServer(t *testing.T, msg pgproto3.BackendMessage) {
	t.Helper()

	r.server.Send(msg)
	require.NoError(t, r.server.Flush())
}

func waitServe(t *testing.T, done <-chan error) error {
	t.Helper()

	select {
	case err := <-done:
		return err
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for the relay to stop")

		return nil
	}
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func encode(t *testing.T, msgs ...pgproto3.Message) []byte {
	t.Helper()

	var encoded []byte

	for _, msg := range msgs {
		var err error

		encoded, err = msg.Encode(encoded)
		require.NoError(t, err)
	}

	return encoded
}

func assertEOF(t *testing.T, reader io.Reader) {
	t.Helper()

	_, err := reader.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

// unknownMessage encodes as a message type pgproto3 cannot decode.
type unknownMessage struct{}

func (unknownMessage) Frontend() {}

func (unknownMessage) Backend() {}

func (unknownMessage) Decode(_ []byte) error { return nil }

func (unknownMessage) Encode(dst []byte) ([]byte, error) {
	return append(dst, 'z', 0, 0, 0, 4), nil
}

type recordingObserver struct {
	mu   sync.Mutex
	seen []string
}

func (o *recordingObserver) onDownstreamMessage(msg pgproto3.FrontendMessage) {
	o.record(fmt.Sprintf("downstream %T", msg))
}

func (o *recordingObserver) onUpstreamMessage(msg pgproto3.BackendMessage) {
	o.record(fmt.Sprintf("upstream %T", msg))
}

func (o *recordingObserver) record(event string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.seen = append(o.seen, event)
}

func (o *recordingObserver) events() []string {
	o.mu.Lock()
	defer o.mu.Unlock()

	return o.seen
}

func TestRelay_Forward(t *testing.T) {
	tests := []struct {
		name        string
		clientSends pgproto3.FrontendMessage
		serverSends pgproto3.BackendMessage
	}{
		{name: "query", clientSends: &pgproto3.Query{String: "SELECT 1"}},
		{name: "copy in data", clientSends: &pgproto3.CopyData{Data: []byte("1\tone\n")}},
		{name: "copy in done", clientSends: &pgproto3.CopyDone{}},
		{name: "data row", serverSends: &pgproto3.DataRow{Values: [][]byte{[]byte("1"), nil}}},
		{name: "copy out data", serverSends: &pgproto3.CopyData{Data: []byte("1\tone\n")}},
		{name: "copy out done", serverSends: &pgproto3.CopyDone{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestRelay(t)
			r.serve(t.Context(), t)

			if tt.clientSends != nil {
				r.sendFromClient(t, tt.clientSends)

				got, err := r.server.Receive()
				require.NoError(t, err)
				assert.Equal(t, tt.clientSends, got)
			}

			if tt.serverSends != nil {
				r.sendFromServer(t, tt.serverSends)

				got, err := r.client.Receive()
				require.NoError(t, err)
				assert.Equal(t, tt.serverSends, got)
			}
		})
	}
}

func TestRelay_Terminate(t *testing.T) {
	r := newTestRelay(t)
	done := r.serve(t.Context(), t)

	r.sendFromClient(t, &pgproto3.Terminate{})

	got, err := r.server.Receive()
	require.NoError(t, err)
	assert.IsType(t, &pgproto3.Terminate{}, got)

	// The server closes its side after a Terminate.
	require.NoError(t, r.serverConn.Close())

	require.NoError(t, waitServe(t, done))
	assertEOF(t, r.clientConn)
}

func TestRelay_PeerCloses(t *testing.T) {
	t.Run("client closes", func(t *testing.T) {
		r := newTestRelay(t)
		done := r.serve(t.Context(), t)

		require.NoError(t, r.clientConn.Close())

		require.NoError(t, waitServe(t, done))
		assertEOF(t, r.serverConn)
	})

	t.Run("server closes", func(t *testing.T) {
		r := newTestRelay(t)
		done := r.serve(t.Context(), t)

		require.NoError(t, r.serverConn.Close())

		require.NoError(t, waitServe(t, done))
		assertEOF(t, r.clientConn)
	})
}

func TestRelay_Close(t *testing.T) {
	r := newTestRelay(t)
	done := r.serve(t.Context(), t)

	r.relay.close()

	require.NoError(t, waitServe(t, done))
	assertEOF(t, r.clientConn)
	assertEOF(t, r.serverConn)
}

func TestRelay_ContextCancelled(t *testing.T) {
	r := newTestRelay(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := r.serve(ctx, t)

	cancel()

	require.NoError(t, waitServe(t, done))
	assertEOF(t, r.clientConn)
	assertEOF(t, r.serverConn)
}

func TestRelay_BufferedMessages(t *testing.T) {
	t.Run("server", func(t *testing.T) {
		r := newTestRelay(t)
		_, err := r.serverConn.Write(encode(t, &pgproto3.AuthenticationOk{}, &pgproto3.ReadyForQuery{TxStatus: 'I'}))
		require.NoError(t, err)

		// Authentication consumes AuthenticationOk and leaves the rest buffered.
		got, err := r.relay.upstream.Frontend.Receive()
		require.NoError(t, err)
		require.IsType(t, &pgproto3.AuthenticationOk{}, got)
		require.Positive(t, r.relay.upstream.Frontend.ReadBufferLen())

		r.serve(t.Context(), t)

		got, err = r.client.Receive()
		require.NoError(t, err)
		assert.Equal(t, &pgproto3.ReadyForQuery{TxStatus: 'I'}, got)
	})

	t.Run("client", func(t *testing.T) {
		r := newTestRelay(t)
		_, err := r.clientConn.Write(encode(t, &pgproto3.PasswordMessage{Password: "secret"}, &pgproto3.Sync{}))
		require.NoError(t, err)

		got, err := r.relay.downstream.backend.Receive()
		require.NoError(t, err)
		require.IsType(t, &pgproto3.PasswordMessage{}, got)

		r.serve(t.Context(), t)

		got, err = r.server.Receive()
		require.NoError(t, err)
		assert.Equal(t, &pgproto3.Sync{}, got)
	})
}

func TestRelay_Observers(t *testing.T) {
	first, second := &recordingObserver{}, &recordingObserver{}
	r := newTestRelay(t, first, second)
	r.serve(t.Context(), t)

	for _, msg := range []pgproto3.FrontendMessage{&pgproto3.Parse{}, &pgproto3.Sync{}} {
		r.sendFromClient(t, msg)

		_, err := r.server.Receive()
		require.NoError(t, err)
	}

	for _, msg := range []pgproto3.BackendMessage{&pgproto3.ParseComplete{}, &pgproto3.ReadyForQuery{TxStatus: 'I'}} {
		r.sendFromServer(t, msg)

		_, err := r.client.Receive()
		require.NoError(t, err)
	}

	want := []string{
		"downstream *pgproto3.Parse",
		"downstream *pgproto3.Sync",
		"upstream *pgproto3.ParseComplete",
		"upstream *pgproto3.ReadyForQuery",
	}
	assert.Equal(t, want, first.events())
	assert.Equal(t, want, second.events())
}

func TestRelay_Error(t *testing.T) {
	tests := []struct {
		name        string
		setupRelay  func(r *relay)
		clientSends pgproto3.FrontendMessage
		serverSends pgproto3.BackendMessage
		wantErr     error
	}{
		{
			name:        "client sends an unknown message",
			clientSends: unknownMessage{},
			wantErr:     errFailedToReceiveDownstreamMessage,
		},
		{
			name:        "server sends an unknown message",
			serverSends: unknownMessage{},
			wantErr:     errFailedToReceiveUpstreamMessage,
		},
		{
			name: "forwarding to the server fails",
			setupRelay: func(r *relay) {
				r.upstream.Frontend = pgproto3.NewFrontend(r.upstream.Conn, &failingWriter{})
			},
			clientSends: &pgproto3.Sync{},
			wantErr:     errFailedToForwardDownstreamMessage,
		},
		{
			name: "forwarding to the client fails",
			setupRelay: func(r *relay) {
				r.downstream.backend = pgproto3.NewBackend(r.downstream.conn, &failingWriter{})
			},
			serverSends: &pgproto3.ReadyForQuery{TxStatus: 'I'},
			wantErr:     errFailedToForwardUpstreamMessage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestRelay(t)

			if tt.setupRelay != nil {
				tt.setupRelay(r.relay)
			}

			done := r.serve(t.Context(), t)

			if tt.clientSends != nil {
				r.sendFromClient(t, tt.clientSends)
			}

			if tt.serverSends != nil {
				r.sendFromServer(t, tt.serverSends)
			}

			assert.ErrorIs(t, waitServe(t, done), tt.wantErr)
		})
	}
}
