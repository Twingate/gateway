// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"
)

var (
	errFailedToReceiveAuthenticationMessage = errors.New("failed to receive authentication message")
	errFailedToSendAuthenticationMessage    = errors.New("failed to send authentication message")
	errUnexpectedAuthenticationMessage      = errors.New("unexpected authentication message")
	errUnsupportedAuthenticationMethod      = errors.New("unsupported authentication method")
)

// authenticationRefusedError is the ErrorResponse that rejected the login.
type authenticationRefusedError struct {
	response pgproto3.ErrorResponse
}

func (e *authenticationRefusedError) Error() string {
	return fmt.Sprintf("authentication refused: %s (SQLSTATE %s)", e.response.Message, e.response.Code)
}

// authenticator answers the upstream's authentication requests after the StartupMessage.
type authenticator struct {
	frontend *pgproto3.Frontend
	password string
}

func newAuthenticator(frontend *pgproto3.Frontend, password string) *authenticator {
	return &authenticator{frontend: frontend, password: password}
}

func (a *authenticator) authenticateWithCleartextPassword() error {
	var request *pgproto3.AuthenticationCleartextPassword

	if err := a.receive(&request); err != nil {
		return err
	}

	if err := a.send(&pgproto3.PasswordMessage{Password: a.password}); err != nil {
		return err
	}

	var accepted *pgproto3.AuthenticationOk

	return a.receive(&accepted)
}

// send sends a message to the upstream and flushes the frontend.
func (a *authenticator) send(msg pgproto3.FrontendMessage) error {
	a.frontend.Send(msg)

	if err := a.frontend.Flush(); err != nil {
		return fmt.Errorf("%w: %w", errFailedToSendAuthenticationMessage, err)
	}

	return nil
}

// receive stores the upstream's next message in target and refuses a message of any other type.
func (a *authenticator) receive[T pgproto3.BackendMessage](target *T) error {
	for {
		msg, err := a.frontend.Receive()
		if err != nil {
			return fmt.Errorf("%w: %w", errFailedToReceiveAuthenticationMessage, err)
		}

		if request, ok := msg.(T); ok {
			*target = request

			return nil
		}

		switch msg := msg.(type) {
		case *pgproto3.NoticeResponse:
			// A notice can arrive at any time and does not change the authentication.
		case *pgproto3.ErrorResponse:
			return &authenticationRefusedError{response: *msg}
		case *pgproto3.AuthenticationOk:
			// The upstream requires no authentication, or accepted before the chosen method finished.
			return fmt.Errorf("%w: expected %T, got %T", errUnexpectedAuthenticationMessage, *target, msg)
		case pgproto3.AuthenticationResponseMessage:
			// Any other authentication message means the upstream is authenticating differently from
			// the chosen method: it asked for another method, or continued one that was not started.
			return fmt.Errorf("%w: expected %T, got %T", errUnsupportedAuthenticationMethod, *target, msg)
		default:
			return fmt.Errorf("%w: expected %T, got %T", errUnexpectedAuthenticationMessage, *target, msg)
		}
	}
}
