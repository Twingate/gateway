// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"bytes"
	"io"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingWriter accepts up to maxWrites writes, then fails every write.
type failingWriter struct {
	maxWrites int
	writes    int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.writes == w.maxWrites {
		return 0, io.ErrClosedPipe
	}

	w.writes++

	return len(p), nil
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

func newTestFrontend(t *testing.T, w io.Writer, received ...pgproto3.Message) *pgproto3.Frontend {
	t.Helper()

	return pgproto3.NewFrontend(bytes.NewReader(encode(t, received...)), w)
}

func TestAuthenticator_AuthenticateWithCleartextPassword(t *testing.T) {
	var sent bytes.Buffer

	received := []pgproto3.Message{
		&pgproto3.AuthenticationCleartextPassword{},
		&pgproto3.AuthenticationOk{},
	}

	a := &authenticator{
		frontend: newTestFrontend(t, &sent, received...),
		password: "token",
	}

	require.NoError(t, a.authenticateWithCleartextPassword())
	assert.Equal(t, encode(t, &pgproto3.PasswordMessage{Password: "token"}), sent.Bytes())
}

func TestAuthenticator_AuthenticateWithCleartextPassword_Error(t *testing.T) {
	tests := []struct {
		name     string
		received []pgproto3.Message
		writer   io.Writer
		wantErr  error
	}{
		{
			name:     "SASL requested",
			received: []pgproto3.Message{&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}}},
			wantErr:  errUnsupportedAuthenticationMethod,
		},
		{
			name:     "send fails",
			received: []pgproto3.Message{&pgproto3.AuthenticationCleartextPassword{}},
			writer:   &failingWriter{},
			wantErr:  errFailedToSendAuthenticationMessage,
		},
		{
			name:     "accepted without a password",
			received: []pgproto3.Message{&pgproto3.AuthenticationOk{}},
			wantErr:  errUnexpectedAuthenticationMessage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := tt.writer
			if writer == nil {
				writer = io.Discard
			}

			a := &authenticator{frontend: newTestFrontend(t, writer, tt.received...), password: "token"}

			err := a.authenticateWithCleartextPassword()
			require.ErrorIs(t, err, tt.wantErr)

			// Ensure that the error message does not contain the password
			assert.NotContains(t, err.Error(), "token")
		})
	}
}

func TestAuthenticator_Receive(t *testing.T) {
	tests := []struct {
		name     string
		received []pgproto3.Message
		want     *pgproto3.AuthenticationOk
		wantErr  error
	}{
		{
			name:    "upstream closes",
			wantErr: errFailedToReceiveAuthenticationMessage,
		},
		{
			name: "notice skipped",
			received: []pgproto3.Message{
				&pgproto3.NoticeResponse{Severity: "NOTICE", Code: "00000", Message: "hello"},
				&pgproto3.AuthenticationOk{},
			},
			want: &pgproto3.AuthenticationOk{},
		},
		{
			name:     "another authentication message",
			received: []pgproto3.Message{&pgproto3.AuthenticationMD5Password{}},
			wantErr:  errUnsupportedAuthenticationMethod,
		},
		{
			name:     "unexpected message",
			received: []pgproto3.Message{&pgproto3.ReadyForQuery{TxStatus: 'I'}},
			wantErr:  errUnexpectedAuthenticationMessage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authenticator{frontend: newTestFrontend(t, io.Discard, tt.received...)}

			var got *pgproto3.AuthenticationOk

			err := a.receive(&got)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthenticator_Receive_AuthenticationRefused(t *testing.T) {
	a := &authenticator{frontend: newTestFrontend(t, io.Discard,
		&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: `password authentication failed for user "alice"`},
	)}

	var got *pgproto3.AuthenticationOk

	err := a.receive(&got)

	var refused *authenticationRefusedError
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, "28P01", refused.response.Code)
	assert.EqualError(t, err, `authentication refused: password authentication failed for user "alice" (SQLSTATE 28P01)`)
}
