// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gateway/internal/util/testutil"
)

func TestDownstreamConn_HandleStartupMessage(t *testing.T) {
	startup := &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30, Parameters: map[string]string{"user": "alice"}}

	tests := []struct {
		name       string
		sends      []pgproto3.FrontendMessage
		wantAnswer string
		wantErr    error
	}{
		{name: "startup", sends: []pgproto3.FrontendMessage{startup}},
		{name: "SSL refused", sends: []pgproto3.FrontendMessage{&pgproto3.SSLRequest{}, startup}, wantAnswer: "N"},
		{name: "GSS encryption refused", sends: []pgproto3.FrontendMessage{&pgproto3.GSSEncRequest{}, startup}, wantAnswer: "N"},
		{name: "second SSLRequest", sends: []pgproto3.FrontendMessage{&pgproto3.SSLRequest{}, &pgproto3.SSLRequest{}}, wantAnswer: "N", wantErr: errUnsupportedStartupRequest},
		{name: "second GSSENCRequest", sends: []pgproto3.FrontendMessage{&pgproto3.GSSEncRequest{}, &pgproto3.GSSEncRequest{}}, wantAnswer: "N", wantErr: errUnsupportedStartupRequest},
		{name: "protocol 2.0", sends: []pgproto3.FrontendMessage{&pgproto3.StartupMessage{ProtocolVersion: 2 << 16, Parameters: map[string]string{}}}, wantErr: errFailedToReceiveStartup},
		{name: "replication", sends: []pgproto3.FrontendMessage{&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30, Parameters: map[string]string{"user": "alice", "replication": "database"}}}, wantErr: errReplicationNotSupported},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := testutil.TCPPipe(t)

			client := pgproto3.NewFrontend(clientConn, clientConn)

			for _, msg := range tt.sends {
				client.Send(msg)
			}

			require.NoError(t, client.Flush())

			got, cancel, err := newDownstreamConn(serverConn).handleStartupMessage()
			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, cancel)

			if tt.wantErr == nil {
				assert.Equal(t, startup, got)
			}

			// Closing the server side ends the client's read, so a missing or extra answer fails
			// the assertion instead of blocking.
			require.NoError(t, serverConn.Close())

			answer, err := io.ReadAll(clientConn)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAnswer, string(answer))
		})
	}
}

func TestDownstreamConn_HandleStartupMessage_ClientCloses(t *testing.T) {
	clientConn, serverConn := testutil.TCPPipe(t)

	require.NoError(t, clientConn.Close())

	_, _, err := newDownstreamConn(serverConn).handleStartupMessage()
	require.ErrorIs(t, err, errFailedToReceiveStartup)
}

func TestDownstreamConn_HandleStartupMessage_AnswerFails(t *testing.T) {
	clientConn, serverConn := testutil.TCPPipe(t)

	client := pgproto3.NewFrontend(clientConn, clientConn)
	client.Send(&pgproto3.SSLRequest{})
	require.NoError(t, client.Flush())

	_, _, err := newDownstreamConn(failingConn{Conn: serverConn}).handleStartupMessage()
	require.ErrorIs(t, err, errFailedToAnswerStartupRequest)
}

func TestDownstreamConn_HandleStartupMessage_Cancel(t *testing.T) {
	clientConn, serverConn := testutil.TCPPipe(t)

	cancel := &pgproto3.CancelRequest{ProcessID: 42, SecretKey: []byte{1, 2, 3, 4}}
	client := pgproto3.NewFrontend(clientConn, clientConn)
	client.Send(cancel)
	require.NoError(t, client.Flush())

	startup, got, err := newDownstreamConn(serverConn).handleStartupMessage()
	require.NoError(t, err)
	assert.Nil(t, startup)
	assert.Equal(t, cancel, got)
}

func TestDownstreamConn_NegotiateProtocolVersion(t *testing.T) {
	tests := []struct {
		name           string
		startup        *pgproto3.StartupMessage
		want           *pgproto3.NegotiateProtocolVersion
		wantParameters map[string]string
	}{
		{
			name:           "protocol 3.0",
			startup:        &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30, Parameters: map[string]string{}},
			wantParameters: map[string]string{},
		},
		{
			name:           "protocol 3.2",
			startup:        &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion32, Parameters: map[string]string{}},
			want:           &pgproto3.NegotiateProtocolVersion{NewestMinorProtocol: pgproto3.ProtocolVersion30, UnrecognizedOptions: []string{}},
			wantParameters: map[string]string{},
		},
		{
			name: "protocol extension option",
			startup: &pgproto3.StartupMessage{
				ProtocolVersion: pgproto3.ProtocolVersion30,
				Parameters:      map[string]string{"application_name": "psql", "_pq_.test_option": "on"},
			},
			want:           &pgproto3.NegotiateProtocolVersion{NewestMinorProtocol: pgproto3.ProtocolVersion30, UnrecognizedOptions: []string{"_pq_.test_option"}},
			wantParameters: map[string]string{"application_name": "psql"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := testutil.TCPPipe(t)

			require.NoError(t, newDownstreamConn(serverConn).negotiateProtocolVersion(tt.startup))
			require.NoError(t, serverConn.Close())
			assert.Equal(t, tt.wantParameters, tt.startup.Parameters)

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

func TestDownstreamConn_CompleteLogin(t *testing.T) {
	clientConn, serverConn := testutil.TCPPipe(t)

	dbConn := &pgconn.HijackedConn{
		PID:               42,
		SecretKey:         []byte{1, 2, 3, 4},
		ParameterStatuses: map[string]string{"server_version": "17.0"},
		TxStatus:          'I',
	}

	require.NoError(t, newDownstreamConn(serverConn).completeLogin(dbConn))

	client := pgproto3.NewFrontend(clientConn, clientConn)

	for _, want := range loginMessages {
		got, err := client.Receive()
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
}

func TestDownstreamConn_CompleteLogin_SendFails(t *testing.T) {
	_, serverConn := testutil.TCPPipe(t)

	err := newDownstreamConn(failingConn{Conn: serverConn}).completeLogin(&pgconn.HijackedConn{})

	require.ErrorIs(t, err, errFailedToCompleteLogin)
}

func TestDownstreamConn_MessageTooLong(t *testing.T) {
	clientConn, serverConn := testutil.TCPPipe(t)

	_, err := clientConn.Write(binary.BigEndian.AppendUint32([]byte{'Q'}, maxMessageBodyLen+5))
	require.NoError(t, err)

	_, err = newDownstreamConn(serverConn).backend.Receive()

	var tooLong *pgproto3.ExceededMaxBodyLenErr
	require.ErrorAs(t, err, &tooLong)
}

func TestDownstreamConn_Reject(t *testing.T) {
	clientConn, serverConn := testutil.TCPPipe(t)

	newDownstreamConn(serverConn).reject(errUnknownCredential)

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
