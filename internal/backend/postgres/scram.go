// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
	"github.com/xdg-go/stringprep"
)

const scramSHA256 = "SCRAM-SHA-256"

var (
	errInvalidSCRAMChallenge = errors.New("invalid SCRAM challenge")
	errSCRAMServerUnverified = errors.New("SCRAM server not verified")
)

type scramConversation interface {
	Step(challenge string) (response string, err error)
}

func (a *authenticator) authenticateWithSCRAM() error {
	conversation := newSCRAMClient(a.password).NewConversation()

	return a.scramExchange(conversation)
}

// scramExchange follows the SCRAM exchange defined in RFC 5802.
func (a *authenticator) scramExchange(conversation scramConversation) error {
	var sasl *pgproto3.AuthenticationSASL

	if err := a.receive(&sasl); err != nil {
		return err
	}

	if !slices.Contains(sasl.AuthMechanisms, scramSHA256) {
		return fmt.Errorf("%w: SASL %s", errUnsupportedAuthenticationMethod, strings.Join(sasl.AuthMechanisms, ", "))
	}

	// The first step only builds the client-first-message and cannot fail on a new conversation.
	clientFirst, _ := conversation.Step("")

	if err := a.send(&pgproto3.SASLInitialResponse{AuthMechanism: scramSHA256, Data: []byte(clientFirst)}); err != nil {
		return err
	}

	var serverFirst *pgproto3.AuthenticationSASLContinue

	if err := a.receive(&serverFirst); err != nil {
		return err
	}

	clientFinal, err := conversation.Step(string(serverFirst.Data))
	if err != nil {
		return errInvalidSCRAMChallenge
	}

	if err = a.send(&pgproto3.SASLResponse{Data: []byte(clientFinal)}); err != nil {
		return err
	}

	var serverFinal *pgproto3.AuthenticationSASLFinal

	if err = a.receive(&serverFinal); err != nil {
		return err
	}

	if _, err = conversation.Step(string(serverFinal.Data)); err != nil {
		return errSCRAMServerUnverified
	}

	var accepted *pgproto3.AuthenticationOk

	return a.receive(&accepted)
}

func newSCRAMClient(password string) *scram.Client {
	// The username is empty because PostgreSQL ignores it and uses the one from the StartupMessage.
	client, _ := scram.SHA256.NewClientUnprepped("", normalizePassword(password), "")

	return client
}

func normalizePassword(password string) string {
	prepared, err := stringprep.SASLprep.Prepare(password)
	if err != nil {
		// Use the original password when SASLprep fails, as PostgreSQL does.
		return password
	}

	return prepared
}
