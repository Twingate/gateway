// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
)

const scramMechanism = "SCRAM-SHA-256"

var (
	errAuthUnsupported  = errors.New("unsupported upstream authentication method")
	errUpstreamProtocol = errors.New("unexpected upstream message")
	errSCRAMNoMechanism = errors.New("upstream does not offer SCRAM-SHA-256")
	errSCRAMClient      = errors.New("SCRAM client error")
	errUpstreamResponse = errors.New("upstream authentication error")
)

// scramClientFactory produces SCRAM client conversations. Broken out for tests.
type scramClientFactory interface {
	NewConversation(username, password string) (scramConversation, error)
}

type scramConversation interface {
	Step(challenge string) (string, error)
}

type defaultSCRAMClientFactory struct{}

//nolint:ireturn // factory returns an interface so tests can inject a fake.
func (defaultSCRAMClientFactory) NewConversation(username, password string) (scramConversation, error) {
	client, err := scram.SHA256.NewClient(username, password, "")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSCRAMClient, err)
	}

	return client.NewConversation(), nil
}

// authenticateUpstream drives the upstream PG authentication state machine.
// It returns once the upstream has sent AuthenticationOk, or an error if an
// unsupported auth method is requested or the upstream returns ErrorResponse.
//
// Notices (NoticeResponse) encountered during auth are ignored — PG servers
// occasionally emit them before AuthenticationRequest.
func authenticateUpstream(
	frontend *pgproto3.Frontend,
	username string,
	password string,
	scramFactory scramClientFactory,
) error {
	var conv scramConversation

	for {
		msg, err := frontend.Receive()
		if err != nil {
			return fmt.Errorf("read upstream message: %w", err)
		}

		done, err := handleAuthMessage(frontend, msg, username, password, scramFactory, &conv)
		if err != nil {
			return err
		}

		if done {
			return nil
		}
	}
}

// handleAuthMessage processes one upstream message during the auth phase.
// Returns (done=true, nil) when AuthenticationOk is received.
func handleAuthMessage(
	frontend *pgproto3.Frontend,
	msg pgproto3.BackendMessage,
	username, password string,
	scramFactory scramClientFactory,
	conv *scramConversation,
) (bool, error) {
	switch m := msg.(type) {
	case *pgproto3.NoticeResponse:
		return false, nil

	case *pgproto3.ErrorResponse:
		return false, fmt.Errorf("%w: %s: %s", errUpstreamResponse, m.Code, m.Message)

	case *pgproto3.AuthenticationOk:
		return true, nil

	case *pgproto3.AuthenticationCleartextPassword:
		frontend.Send(&pgproto3.PasswordMessage{Password: password})

		if err := frontend.Flush(); err != nil {
			return false, fmt.Errorf("send cleartext password: %w", err)
		}

		return false, nil

	case *pgproto3.AuthenticationSASL:
		return false, startSCRAM(frontend, m, username, password, scramFactory, conv)

	case *pgproto3.AuthenticationSASLContinue:
		return false, stepSCRAM(frontend, m.Data, *conv)

	case *pgproto3.AuthenticationSASLFinal:
		if *conv == nil {
			return false, fmt.Errorf("%w: SASLFinal before SASL", errUpstreamProtocol)
		}

		if _, err := (*conv).Step(string(m.Data)); err != nil {
			return false, fmt.Errorf("%w: %w", errSCRAMClient, err)
		}

		return false, nil

	case *pgproto3.AuthenticationMD5Password,
		*pgproto3.AuthenticationGSS,
		*pgproto3.AuthenticationGSSContinue:
		return false, fmt.Errorf("%w: %T", errAuthUnsupported, msg)

	default:
		return false, fmt.Errorf("%w: %T", errUpstreamProtocol, msg)
	}
}

func startSCRAM(
	frontend *pgproto3.Frontend,
	msg *pgproto3.AuthenticationSASL,
	username, password string,
	scramFactory scramClientFactory,
	conv *scramConversation,
) error {
	if !slices.Contains(msg.AuthMechanisms, scramMechanism) {
		return fmt.Errorf("%w: offered=%v", errSCRAMNoMechanism, msg.AuthMechanisms)
	}

	newConv, err := scramFactory.NewConversation(username, password)
	if err != nil {
		return err
	}

	*conv = newConv

	clientFirst, err := newConv.Step("")
	if err != nil {
		return fmt.Errorf("%w: %w", errSCRAMClient, err)
	}

	frontend.Send(&pgproto3.SASLInitialResponse{
		AuthMechanism: scramMechanism,
		Data:          []byte(clientFirst),
	})

	if err := frontend.Flush(); err != nil {
		return fmt.Errorf("send SASLInitialResponse: %w", err)
	}

	return nil
}

func stepSCRAM(frontend *pgproto3.Frontend, challenge []byte, conv scramConversation) error {
	if conv == nil {
		return fmt.Errorf("%w: SASLContinue before SASL", errUpstreamProtocol)
	}

	response, err := conv.Step(string(challenge))
	if err != nil {
		return fmt.Errorf("%w: %w", errSCRAMClient, err)
	}

	frontend.Send(&pgproto3.SASLResponse{Data: []byte(response)})

	if err := frontend.Flush(); err != nil {
		return fmt.Errorf("send SASLResponse: %w", err)
	}

	return nil
}
