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

// fakeSCRAM answers each challenge with its entry in responses, and fails on a challenge without one.
type fakeSCRAM struct {
	responses map[string]string
}

func (f fakeSCRAM) Step(challenge string) (string, error) {
	response, ok := f.responses[challenge]
	if !ok {
		return "", assert.AnError
	}

	return response, nil
}

func TestNormalizePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     string
	}{
		{
			name:     "no-break space becomes a space",
			password: "pass word",
			want:     "pass word",
		},
		{
			name:     "prohibited character keeps the password",
			password: "pass\U0001F600word",
			want:     "pass\U0001F600word",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizePassword(tt.password))
		})
	}
}

func TestAuthenticator_AuthenticateWithSCRAM(t *testing.T) {
	var sent bytes.Buffer

	frontend := newTestFrontend(t, &sent, &pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})

	// The exchange stops after the client-first-message because the script has no server-first-message.
	err := newAuthenticator(frontend, "secret").authenticateWithSCRAM()
	require.ErrorIs(t, err, errFailedToReceiveAuthenticationMessage)

	backend := pgproto3.NewBackend(&sent, io.Discard)
	require.NoError(t, backend.SetAuthType(pgproto3.AuthTypeSASL))

	msg, err := backend.Receive()
	require.NoError(t, err)

	clientFirst, ok := msg.(*pgproto3.SASLInitialResponse)
	require.True(t, ok)
	assert.Equal(t, "SCRAM-SHA-256", clientFirst.AuthMechanism)
	assert.Regexp(t, `^n,,n=,r=.+`, string(clientFirst.Data))
}

func TestAuthenticator_ScramExchange(t *testing.T) {
	var sent bytes.Buffer

	a := &authenticator{
		frontend: newTestFrontend(t, &sent,
			&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"}},
			&pgproto3.AuthenticationSASLContinue{Data: []byte("server-first")},
			&pgproto3.AuthenticationSASLFinal{Data: []byte("server-final")},
			&pgproto3.AuthenticationOk{},
		),
		password: "secret",
	}

	responses := map[string]string{"": "client-first", "server-first": "client-final", "server-final": ""}

	require.NoError(t, a.scramExchange(fakeSCRAM{responses: responses}))
	assert.Equal(t, encode(t,
		&pgproto3.SASLInitialResponse{AuthMechanism: "SCRAM-SHA-256", Data: []byte("client-first")},
		&pgproto3.SASLResponse{Data: []byte("client-final")},
	), sent.Bytes())
}

func TestAuthenticator_ScramExchange_Error(t *testing.T) {
	sasl := &pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"}}
	serverFirst := &pgproto3.AuthenticationSASLContinue{Data: []byte("server-first")}
	serverFinal := &pgproto3.AuthenticationSASLFinal{Data: []byte("server-final")}
	responses := map[string]string{"": "client-first", "server-first": "client-final", "server-final": ""}

	tests := []struct {
		name      string
		received  []pgproto3.Message
		responses map[string]string
		writer    io.Writer
		wantErr   error
	}{
		{
			name:     "SCRAM-SHA-256 not offered",
			received: []pgproto3.Message{&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS"}}},
			wantErr:  errUnsupportedAuthenticationMethod,
		},
		{
			name:     "cleartext requested",
			received: []pgproto3.Message{&pgproto3.AuthenticationCleartextPassword{}},
			wantErr:  errUnsupportedAuthenticationMethod,
		},
		{
			name:     "MD5 requested",
			received: []pgproto3.Message{&pgproto3.AuthenticationMD5Password{}},
			wantErr:  errUnsupportedAuthenticationMethod,
		},
		{
			name:     "GSSAPI requested",
			received: []pgproto3.Message{&pgproto3.AuthenticationGSS{}},
			wantErr:  errUnsupportedAuthenticationMethod,
		},
		{
			name:     "accepted without SASL",
			received: []pgproto3.Message{&pgproto3.AuthenticationOk{}},
			wantErr:  errUnexpectedAuthenticationMessage,
		},
		{
			name:      "client-first-message send fails",
			received:  []pgproto3.Message{sasl},
			responses: responses,
			writer:    &failingWriter{},
			wantErr:   errFailedToSendAuthenticationMessage,
		},
		{
			name:      "invalid challenge",
			received:  []pgproto3.Message{sasl, serverFirst},
			responses: map[string]string{"": "client-first"},
			wantErr:   errInvalidSCRAMChallenge,
		},
		{
			name:      "client-final-message send fails",
			received:  []pgproto3.Message{sasl, serverFirst},
			responses: responses,
			writer:    &failingWriter{maxWrites: 1},
			wantErr:   errFailedToSendAuthenticationMessage,
		},
		{
			name:      "accepted without a server-final-message",
			received:  []pgproto3.Message{sasl, serverFirst, &pgproto3.AuthenticationOk{}},
			responses: responses,
			wantErr:   errUnexpectedAuthenticationMessage,
		},
		{
			name:      "invalid server-final-message",
			received:  []pgproto3.Message{sasl, serverFirst, serverFinal},
			responses: map[string]string{"": "client-first", "server-first": "client-final"},
			wantErr:   errSCRAMServerUnverified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := tt.writer
			if writer == nil {
				writer = io.Discard
			}

			a := &authenticator{frontend: newTestFrontend(t, writer, tt.received...), password: "secret"}

			err := a.scramExchange(fakeSCRAM{responses: tt.responses})
			require.ErrorIs(t, err, tt.wantErr)

			// Ensure that the error message does not contain the password
			assert.NotContains(t, err.Error(), "secret")
		})
	}
}
