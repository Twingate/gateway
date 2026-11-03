// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

const (
	// encryptionRefused answers an SSLRequest or GSSENCRequest.
	encryptionRefused = 'N'

	severityFatal = "FATAL"

	// maxMessageBodyLen follows PostgreSQL's own 1 GiB message limit.
	maxMessageBodyLen = 0x3fffffff - 1
)

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
	backend := pgproto3.NewBackend(conn, conn)

	// Protects against malicious clients that send large messages.
	backend.SetMaxBodyLen(maxMessageBodyLen)

	return &downstreamConn{conn: conn, backend: backend}
}

// handleStartupMessage refuses SSLRequest and GSSENCRequest, then returns the StartupMessage or
// the CancelRequest that follows.
func (c *downstreamConn) handleStartupMessage() (*pgproto3.StartupMessage, *pgproto3.CancelRequest, error) {
	_ = c.conn.SetDeadline(time.Now().Add(defaultTimeout))

	defer func() { _ = c.conn.SetDeadline(time.Time{}) }()

	// A client that repeats a refused request is rejected.
	refused := map[string]bool{}

	for {
		msg, err := c.backend.ReceiveStartupMessage()
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", errFailedToReceiveStartup, err)
		}

		switch msg := msg.(type) {
		case *pgproto3.StartupMessage:
			return msg, nil, nil
		case *pgproto3.CancelRequest:
			return nil, msg, nil
		case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest:
			request := fmt.Sprintf("%T", msg)
			if refused[request] {
				return nil, nil, fmt.Errorf("%w: repeated %s", errUnsupportedStartupRequest, request)
			}

			refused[request] = true

			// Refuse encryption and tell client to fall back to plaintext on the same connection.
			if _, err := c.conn.Write([]byte{encryptionRefused}); err != nil {
				return nil, nil, fmt.Errorf("%w: %w", errFailedToAnswerStartupRequest, err)
			}
		default:
			return nil, nil, fmt.Errorf("%w: %T", errUnsupportedStartupRequest, msg)
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

// completeLogin tells the client it is logged in, with the session state the upstream login
// consumed: the parameters, the cancel key, and the ReadyForQuery.
func (c *downstreamConn) completeLogin(dbConn *pgconn.HijackedConn) error {
	// Bounds the flush to a client that stops reading. The relay writes to the client next, so
	// the deadline is cleared once the login is complete.
	_ = c.conn.SetWriteDeadline(time.Now().Add(defaultTimeout))

	defer func() { _ = c.conn.SetWriteDeadline(time.Time{}) }()

	c.backend.Send(&pgproto3.AuthenticationOk{})

	for name, value := range dbConn.ParameterStatuses {
		c.backend.Send(&pgproto3.ParameterStatus{Name: name, Value: value})
	}

	c.backend.Send(&pgproto3.BackendKeyData{ProcessID: dbConn.PID, SecretKey: dbConn.SecretKey})
	c.backend.Send(&pgproto3.ReadyForQuery{TxStatus: dbConn.TxStatus})

	if err := c.backend.Flush(); err != nil {
		return fmt.Errorf("%w: %w", errFailedToCompleteLogin, err)
	}

	return nil
}

// reject tells the client why its connection failed, closes the connection, and returns err. A
// failed write is ignored, since the connection is closed either way.
func (c *downstreamConn) reject(err error) error {
	// Bounds the flush to a client that stops reading.
	_ = c.conn.SetWriteDeadline(time.Now().Add(defaultTimeout))

	c.backend.Send(newErrorResponse(err))
	_ = c.backend.Flush()
	_ = c.conn.Close()

	return err
}

func newErrorResponse(err error) *pgproto3.ErrorResponse {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if ok {
		return &pgproto3.ErrorResponse{
			Severity: pgErr.Severity,
			Code:     pgErr.Code,
			Message:  pgErr.Message,
			Detail:   pgErr.Detail,
		}
	}

	return &pgproto3.ErrorResponse{
		Severity:            severityFatal,
		SeverityUnlocalized: severityFatal,
		Message:             err.Error(),
	}
}
