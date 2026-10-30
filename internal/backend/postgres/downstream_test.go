// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingConn fails every write.
type failingConn struct {
	net.Conn
}

func (failingConn) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

// tcpPipe is net.Pipe over a loopback TCP connection, whose writes are buffered instead of blocking
// until the other end reads.
func tcpPipe(t *testing.T) func() (net.Conn, net.Conn) {
	t.Helper()

	return func() (net.Conn, net.Conn) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		defer listener.Close()

		client, err := net.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)

		server, err := listener.Accept()
		require.NoError(t, err)

		return client, server
	}
}

func TestDownstreamConn_ReceiveStartupRequest(t *testing.T) {
	startup := &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30, Parameters: map[string]string{"user": "alice"}}

	tests := []struct {
		name    string
		sends   []pgproto3.FrontendMessage
		wantErr error
	}{
		{name: "startup", sends: []pgproto3.FrontendMessage{startup}},
		{name: "SSL refused", sends: []pgproto3.FrontendMessage{&pgproto3.SSLRequest{}, startup}},
		{name: "GSS encryption refused", sends: []pgproto3.FrontendMessage{&pgproto3.GSSEncRequest{}, startup}},
		{name: "second SSLRequest", sends: []pgproto3.FrontendMessage{&pgproto3.SSLRequest{}, &pgproto3.SSLRequest{}}, wantErr: errUnsupportedStartupRequest},
		{name: "second GSSENCRequest", sends: []pgproto3.FrontendMessage{&pgproto3.GSSEncRequest{}, &pgproto3.GSSEncRequest{}}, wantErr: errUnsupportedStartupRequest},
		{name: "protocol 2.0", sends: []pgproto3.FrontendMessage{&pgproto3.StartupMessage{ProtocolVersion: 2 << 16, Parameters: map[string]string{}}}, wantErr: errFailedToReceiveStartup},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := tcpPipe(t)()
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})

			client := pgproto3.NewFrontend(clientConn, clientConn)

			for _, msg := range tt.sends {
				client.Send(msg)
			}

			require.NoError(t, client.Flush())

			got, cancel, err := newDownstreamConn(serverConn).receiveStartupRequest()
			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, cancel)

			if tt.wantErr == nil {
				assert.Equal(t, startup, got)
			}
		})
	}
}

func TestDownstreamConn_ReceiveStartupRequest_ClientCloses(t *testing.T) {
	clientConn, serverConn := tcpPipe(t)()
	t.Cleanup(func() { _ = serverConn.Close() })

	require.NoError(t, clientConn.Close())

	_, _, err := newDownstreamConn(serverConn).receiveStartupRequest()
	require.ErrorIs(t, err, errFailedToReceiveStartup)
}

func TestDownstreamConn_ReceiveStartupRequest_AnswerFails(t *testing.T) {
	clientConn, serverConn := tcpPipe(t)()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	client := pgproto3.NewFrontend(clientConn, clientConn)
	client.Send(&pgproto3.SSLRequest{})
	require.NoError(t, client.Flush())

	_, _, err := newDownstreamConn(failingConn{Conn: serverConn}).receiveStartupRequest()
	require.ErrorIs(t, err, errFailedToAnswerStartupRequest)
}

func TestDownstreamConn_ReceiveStartupRequest_Cancel(t *testing.T) {
	clientConn, serverConn := tcpPipe(t)()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	cancel := &pgproto3.CancelRequest{ProcessID: 42, SecretKey: []byte{1, 2, 3, 4}}
	client := pgproto3.NewFrontend(clientConn, clientConn)
	client.Send(cancel)
	require.NoError(t, client.Flush())

	startup, got, err := newDownstreamConn(serverConn).receiveStartupRequest()
	require.NoError(t, err)
	assert.Nil(t, startup)
	assert.Equal(t, cancel, got)
}

func TestDownstreamConn_NegotiateProtocolVersion(t *testing.T) {
	tests := []struct {
		name    string
		startup *pgproto3.StartupMessage
		want    *pgproto3.NegotiateProtocolVersion
	}{
		{
			name:    "protocol 3.0",
			startup: &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30, Parameters: map[string]string{}},
		},
		{
			name:    "protocol 3.2",
			startup: &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion32, Parameters: map[string]string{}},
			want:    &pgproto3.NegotiateProtocolVersion{NewestMinorProtocol: pgproto3.ProtocolVersion30, UnrecognizedOptions: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := tcpPipe(t)()
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})

			require.NoError(t, newDownstreamConn(serverConn).negotiateProtocolVersion(tt.startup))
			require.NoError(t, serverConn.Close())

			client := pgproto3.NewFrontend(clientConn, clientConn)

			if tt.want == nil {
				_, err := clientConn.Read(make([]byte, 1))
				assert.ErrorIs(t, err, io.EOF)

				return
			}

			got, err := client.Receive()
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDownstreamConn_NegotiateProtocolVersion_SendFails(t *testing.T) {
	startup := &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion32, Parameters: map[string]string{}}

	err := newDownstreamConn(failingConn{}).negotiateProtocolVersion(startup)

	require.ErrorIs(t, err, errFailedToNegotiateProtocol)
}

func TestDownstreamConn_Accept(t *testing.T) {
	clientConn, serverConn := tcpPipe(t)()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	upstreamConn := &pgconn.HijackedConn{
		PID:               42,
		SecretKey:         []byte{1, 2, 3, 4},
		ParameterStatuses: map[string]string{"server_version": "17.0"},
		TxStatus:          'I',
	}

	require.NoError(t, newDownstreamConn(serverConn).accept(upstreamConn))

	client := pgproto3.NewFrontend(clientConn, clientConn)

	for _, want := range []pgproto3.BackendMessage{
		&pgproto3.AuthenticationOk{},
		&pgproto3.ParameterStatus{Name: "server_version", Value: "17.0"},
		&pgproto3.BackendKeyData{ProcessID: 42, SecretKey: []byte{1, 2, 3, 4}},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	} {
		got, err := client.Receive()
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
}

func TestDownstreamConn_Accept_SendFails(t *testing.T) {
	require.ErrorIs(t, newDownstreamConn(failingConn{}).accept(&pgconn.HijackedConn{}), errFailedToCompleteLogin)
}

func TestDownstreamConn_MessageTooLong(t *testing.T) {
	clientConn, serverConn := tcpPipe(t)()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	_, err := clientConn.Write(binary.BigEndian.AppendUint32([]byte{'Q'}, maxMessageBodyLen+5))
	require.NoError(t, err)

	_, err = newDownstreamConn(serverConn).backend.Receive()

	var tooLong *pgproto3.ExceededMaxBodyLenErr
	require.ErrorAs(t, err, &tooLong)
}

func TestDownstreamConn_Reject(t *testing.T) {
	clientConn, serverConn := tcpPipe(t)()
	t.Cleanup(func() { _ = clientConn.Close() })

	require.ErrorIs(t, newDownstreamConn(serverConn).reject(errUnknownCredential), errUnknownCredential)

	got, err := pgproto3.NewFrontend(clientConn, clientConn).Receive()
	require.NoError(t, err)
	assert.Equal(t, newErrorResponse(errUnknownCredential), got)

	_, err = clientConn.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

func TestNewErrorResponse(t *testing.T) {
	pgErr := &pgconn.PgError{Severity: "FATAL", Code: "3D000", Message: `database "app" does not exist`, Detail: "detail"}

	tests := []struct {
		name string
		err  error
		want *pgproto3.ErrorResponse
	}{
		{
			name: "database error",
			err:  fmt.Errorf("%w: %w", errFailedToConnectUpstream, pgErr),
			want: &pgproto3.ErrorResponse{Severity: "FATAL", Code: "3D000", Message: `database "app" does not exist`, Detail: "detail"},
		},
		{
			name: "gateway error",
			err:  errUnknownCredential,
			want: &pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Message: "unknown credential"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, newErrorResponse(tt.err))
		})
	}
}
