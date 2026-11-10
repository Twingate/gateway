// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"gateway/internal/token"
)

const (
	testCredential      = "test"
	testDatabaseUser    = "gateway"
	testCertificateFile = "../../../test/data/proxy/tls.crt"
	testPrivateKeyFile  = "../../../test/data/proxy/tls.key"

	// testTimeout bounds every blocking wait in these tests.
	testTimeout = 5 * time.Second
)

var passwordAuth = token.Auth{
	Type:     token.AuthTypePassword,
	User:     testDatabaseUser,
	Password: &token.PasswordAuth{Credential: testCredential},
}

// loginMessages is the session state a fake database sends once it accepts the login, and what
// the client receives once the proxy completes the login.
var loginMessages = []pgproto3.BackendMessage{
	&pgproto3.AuthenticationOk{},
	&pgproto3.ParameterStatus{Name: "server_version", Value: "17.0"},
	&pgproto3.BackendKeyData{ProcessID: 42, SecretKey: []byte{1, 2, 3, 4}},
	&pgproto3.ReadyForQuery{TxStatus: 'I'},
}

// failingConn fails every write.
type failingConn struct {
	net.Conn
}

func (failingConn) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func waitServe(t *testing.T, done <-chan error) error {
	t.Helper()

	select {
	case err := <-done:
		return err
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for serve to return")

		return nil
	}
}
