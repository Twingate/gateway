// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xdg-go/scram"
)

const testSCRAMPassword = "s3cret"

// runAuthenticator drives authenticateUpstream against a scripted server that
// writes messages via `serverScript` and runs on the other end of a net.Pipe.
func runAuthenticator(
	t *testing.T,
	serverScript func(srv *pgproto3.Backend, raw net.Conn),
) error {
	t.Helper()

	clientSide, serverSide := net.Pipe()

	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
	})

	// Safety net against a hung test if the script misbehaves.
	deadline := time.Now().Add(5 * time.Second)
	_ = clientSide.SetDeadline(deadline)
	_ = serverSide.SetDeadline(deadline)

	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)

		srvBackend := pgproto3.NewBackend(serverSide, serverSide)
		serverScript(srvBackend, serverSide)
	}()

	frontend := pgproto3.NewFrontend(clientSide, clientSide)
	err := authenticateUpstream(frontend, "svc", testSCRAMPassword, defaultSCRAMClientFactory{})

	<-serverDone

	return err
}

func TestAuthenticateUpstream_CleartextHappyPath(t *testing.T) {
	err := runAuthenticator(t, func(srv *pgproto3.Backend, _ net.Conn) {
		srv.Send(&pgproto3.AuthenticationCleartextPassword{})
		require.NoError(t, srv.Flush())
		require.NoError(t, srv.SetAuthType(pgproto3.AuthTypeCleartextPassword))

		msg, err := srv.Receive()
		require.NoError(t, err)

		pwMsg, ok := msg.(*pgproto3.PasswordMessage)
		require.True(t, ok, "expected PasswordMessage, got %T", msg)
		assert.Equal(t, testSCRAMPassword, pwMsg.Password)

		srv.Send(&pgproto3.AuthenticationOk{})
		require.NoError(t, srv.Flush())
	})

	require.NoError(t, err)
}

func TestAuthenticateUpstream_SCRAMHappyPath(t *testing.T) {
	err := runAuthenticator(t, func(srv *pgproto3.Backend, _ net.Conn) {
		srv.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{scramMechanism}})
		require.NoError(t, srv.Flush())
		require.NoError(t, srv.SetAuthType(pgproto3.AuthTypeSASL))

		// Build server-side SCRAM credentials for the known test password.
		knownClient, err := scram.SHA256.NewClient("svc", testSCRAMPassword, "")
		require.NoError(t, err)

		storedCreds, err := knownClient.GetStoredCredentialsWithError(scram.KeyFactors{Salt: "salt", Iters: 4096})
		require.NoError(t, err)

		server, err := scram.SHA256.NewServer(func(string) (scram.StoredCredentials, error) {
			return storedCreds, nil
		})
		require.NoError(t, err)

		conv := server.NewConversation()

		// client-first
		msg, err := srv.Receive()
		require.NoError(t, err)

		initial, ok := msg.(*pgproto3.SASLInitialResponse)
		require.True(t, ok, "expected SASLInitialResponse, got %T", msg)
		assert.Equal(t, scramMechanism, initial.AuthMechanism)

		serverFirst, err := conv.Step(string(initial.Data))
		require.NoError(t, err)

		srv.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte(serverFirst)})
		require.NoError(t, srv.Flush())
		require.NoError(t, srv.SetAuthType(pgproto3.AuthTypeSASLContinue))

		// client-final
		msg, err = srv.Receive()
		require.NoError(t, err)

		final, ok := msg.(*pgproto3.SASLResponse)
		require.True(t, ok, "expected SASLResponse, got %T", msg)

		serverFinal, err := conv.Step(string(final.Data))
		require.NoError(t, err)

		srv.Send(&pgproto3.AuthenticationSASLFinal{Data: []byte(serverFinal)})
		require.NoError(t, srv.Flush())

		srv.Send(&pgproto3.AuthenticationOk{})
		require.NoError(t, srv.Flush())
	})

	require.NoError(t, err)
}

func TestAuthenticateUpstream_NoticeIgnored(t *testing.T) {
	err := runAuthenticator(t, func(srv *pgproto3.Backend, _ net.Conn) {
		srv.Send(&pgproto3.NoticeResponse{Severity: "NOTICE", Message: "hello"})
		srv.Send(&pgproto3.AuthenticationOk{})
		require.NoError(t, srv.Flush())
	})

	require.NoError(t, err)
}

func TestAuthenticateUpstream_MD5Unsupported(t *testing.T) {
	err := runAuthenticator(t, func(srv *pgproto3.Backend, _ net.Conn) {
		srv.Send(&pgproto3.AuthenticationMD5Password{Salt: [4]byte{1, 2, 3, 4}})
		require.NoError(t, srv.Flush())
	})

	require.Error(t, err)
	require.ErrorIs(t, err, errAuthUnsupported)
}

func TestAuthenticateUpstream_UnsupportedSASLMechanism(t *testing.T) {
	err := runAuthenticator(t, func(srv *pgproto3.Backend, _ net.Conn) {
		srv.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256-PLUS"}})
		require.NoError(t, srv.Flush())
	})

	require.Error(t, err)
	require.ErrorIs(t, err, errSCRAMNoMechanism)
}

func TestAuthenticateUpstream_ErrorResponse(t *testing.T) {
	err := runAuthenticator(t, func(srv *pgproto3.Backend, _ net.Conn) {
		srv.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "bad password"})
		require.NoError(t, srv.Flush())
	})

	require.Error(t, err)
	require.ErrorIs(t, err, errUpstreamResponse)
	assert.Contains(t, err.Error(), "bad password")
}

func TestAuthenticateUpstream_UpstreamClosedBeforeOK(t *testing.T) {
	err := runAuthenticator(t, func(_ *pgproto3.Backend, raw net.Conn) {
		_ = raw.Close()
	})

	require.Error(t, err)
	// Any I/O error here is fine — EOF, closed pipe, etc.
	assert.True(t, errors.Is(err, net.ErrClosed) || err.Error() != "", "expected an I/O error, got %v", err)
}
