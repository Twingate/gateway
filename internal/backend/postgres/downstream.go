// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"errors"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// sslNotSupported answers an SSLRequest or GSSENCRequest.
const sslNotSupported = 'N'

var (
	errUnsupportedStartupRequest    = errors.New("unsupported startup request")
	errFailedToReceiveStartup       = errors.New("failed to receive startup message")
	errFailedToAnswerStartupRequest = errors.New("failed to answer startup request")
	errFailedToNegotiateProtocol    = errors.New("failed to send NegotiateProtocolVersion")
	errFailedToCompleteLogin        = errors.New("failed to complete client login")
)

type downstreamConn struct {
	conn    net.Conn
	backend *pgproto3.Backend
}

func newDownstreamConn(conn net.Conn) *downstreamConn {
	return &downstreamConn{conn: conn, backend: pgproto3.NewBackend(conn, conn)}
}

// receiveStartupRequest answers SSLRequest and GSSENCRequest, then returns the
// StartupMessage or the CancelRequest that follows.
func (c *downstreamConn) receiveStartupRequest() (*pgproto3.StartupMessage, *pgproto3.CancelRequest, error) {
	// The first request of each kind is refused with N rather than failed, because the client can
	// fall back to plaintext. A repeat means it ignored the refusal.
	var sslRequested, gssRequested bool

	for {
		msg, err := c.backend.ReceiveStartupMessage()
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", errFailedToReceiveStartup, err)
		}

		switch msg := msg.(type) {
		case *pgproto3.SSLRequest:
			if sslRequested {
				return nil, nil, fmt.Errorf("%w: SSLRequest", errUnsupportedStartupRequest)
			}

			sslRequested = true
		case *pgproto3.GSSEncRequest:
			if gssRequested {
				return nil, nil, fmt.Errorf("%w: GSSENCRequest", errUnsupportedStartupRequest)
			}

			gssRequested = true
		case *pgproto3.StartupMessage:
			return msg, nil, nil
		case *pgproto3.CancelRequest:
			return nil, msg, nil
		default:
			return nil, nil, fmt.Errorf("%w: %T", errUnsupportedStartupRequest, msg)
		}

		if _, err := c.conn.Write([]byte{sslNotSupported}); err != nil {
			return nil, nil, fmt.Errorf("%w: %w", errFailedToAnswerStartupRequest, err)
		}
	}
}

// negotiateProtocolVersion always downgrades the connection to protocol 3.0.
func (c *downstreamConn) negotiateProtocolVersion(startup *pgproto3.StartupMessage) error {
	if startup.ProtocolVersion == pgproto3.ProtocolVersion30 {
		return nil
	}

	// The field carries the whole version number, as the server sends it: libpq reads a bare 0 as
	// protocol 0.0, not as minor version 0, and refuses it.
	c.backend.Send(&pgproto3.NegotiateProtocolVersion{NewestMinorProtocol: pgproto3.ProtocolVersion30})

	if err := c.backend.Flush(); err != nil {
		return fmt.Errorf("%w: %w", errFailedToNegotiateProtocol, err)
	}

	return nil
}

// accept tells the client it is logged in, with the session state the upstream login consumed:
// the parameters, the cancel key, and the ReadyForQuery.
func (c *downstreamConn) accept(upstream *pgconn.HijackedConn) error {
	c.backend.Send(&pgproto3.AuthenticationOk{})

	for name, value := range upstream.ParameterStatuses {
		c.backend.Send(&pgproto3.ParameterStatus{Name: name, Value: value})
	}

	c.backend.Send(&pgproto3.BackendKeyData{ProcessID: upstream.PID, SecretKey: upstream.SecretKey})
	c.backend.Send(&pgproto3.ReadyForQuery{TxStatus: upstream.TxStatus})

	if err := c.backend.Flush(); err != nil {
		return fmt.Errorf("%w: %w", errFailedToCompleteLogin, err)
	}

	return nil
}
