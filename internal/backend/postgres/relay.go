// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
)

// maxAuditPayload bounds the SQL text or the combined parameter bytes carried
// by one audit line. Messages are forwarded whole regardless of the bound.
const maxAuditPayload = 64 * 1024

// relay forwards Postgres messages in both directions until either side closes.
// Using pgproto3 framing (rather than raw io.Copy) keeps the solution correct
// in the presence of pgproto3's internal chunkReader buffer, which may hold
// bytes read past the last auth-phase message.
//
// downConn and upConn are needed so that when one direction errors we can
// eagerly close the sockets and wake the other goroutine.
func relay(
	ctx context.Context,
	logger *zap.Logger,
	downConn net.Conn,
	upConn net.Conn,
	backend *pgproto3.Backend,
	frontend *pgproto3.Frontend,
) error {
	g, gCtx := errgroup.WithContext(ctx)

	// Upstream → Client: forward BackendMessages from the PG server to the client.
	g.Go(func() error {
		// One request's worth of buffered results. Flushed to the audit log on
		// ReadyForQuery — the natural "client submitted something, here's what
		// came back" boundary.
		buf := &requestBuf{}

		for {
			if err := gCtx.Err(); err != nil {
				return err
			}

			msg, err := frontend.Receive()
			if err != nil {
				return wrapRelayErr("read upstream", err)
			}

			logServerMessage(logger, msg, buf)

			backend.Send(msg)

			if err := backend.Flush(); err != nil {
				return wrapRelayErr("write downstream", err)
			}
		}
	})

	// Client → Upstream: forward FrontendMessages from the client to the PG server.
	g.Go(func() error {
		for {
			if err := gCtx.Err(); err != nil {
				return err
			}

			msg, err := backend.Receive()
			if err != nil {
				return wrapRelayErr("read downstream", err)
			}

			logClientMessage(logger, msg)

			frontend.Send(msg)

			if err := frontend.Flush(); err != nil {
				return wrapRelayErr("write upstream", err)
			}

			// A Terminate message means the client is done; close cleanly.
			if _, isTerminate := msg.(*pgproto3.Terminate); isTerminate {
				return nil
			}
		}
	})

	// When either direction exits, close both sockets so the sibling goroutine unblocks.
	go func() {
		<-gCtx.Done()

		_ = downConn.Close()
		_ = upConn.Close()
	}()

	err := g.Wait()
	if isBenignRelayErr(err) {
		return nil
	}

	return err
}

func wrapRelayErr(direction string, err error) error {
	return fmt.Errorf("%s: %w", direction, err)
}

// logClientMessage emits an audit line for each client message that carries
// user intent. Simple Query and extended-protocol Parse carry SQL text, Bind
// carries the parameter values, Execute names the portal to run, and
// FunctionCall invokes a server function directly. Statement and portal names
// are logged as sent; an Execute is attributed to its SQL through the Parse
// and Bind lines that precede it on the same connection.
func logClientMessage(logger *zap.Logger, msg pgproto3.FrontendMessage) {
	switch m := msg.(type) {
	case *pgproto3.Query:
		logger.Info("pg query", sqlFields(m.String)...)
	case *pgproto3.Parse:
		fields := []zap.Field{zap.String("name", m.Name)}
		logger.Info("pg parse", append(fields, sqlFields(m.Query)...)...)
	case *pgproto3.Bind:
		fields := []zap.Field{
			zap.String("statement", m.PreparedStatement),
			zap.String("portal", m.DestinationPortal),
		}
		logger.Info("pg bind", append(fields, valueFields("parameters", m.Parameters, m.ParameterFormatCodes)...)...)
	case *pgproto3.Execute:
		logger.Info("pg execute", zap.String("portal", m.Portal), zap.Uint32("max_rows", m.MaxRows))
	case *pgproto3.FunctionCall:
		fields := []zap.Field{zap.Uint32("function", m.Function)}
		logger.Info("pg function_call", append(fields, valueFields("arguments", m.Arguments, m.ArgFormatCodes)...)...)
	default:
		// Describe, Close, Sync, Flush, CopyData, CopyDone, CopyFail and
		// Terminate carry no user intent and are not logged.
	}
}

// sqlFields renders SQL text cut to maxAuditPayload bytes, flagging the cut.
func sqlFields(sql string) []zap.Field {
	if len(sql) <= maxAuditPayload {
		return []zap.Field{zap.String("sql", sql)}
	}

	return []zap.Field{zap.String("sql", sql[:maxAuditPayload]), zap.Bool("truncated", true)}
}

// valueFields renders Bind parameters or FunctionCall arguments under key.
// Text-format values are logged as strings, binary ones as base64 and NULL as
// JSON null. Values are appended until maxAuditPayload bytes have been spent;
// the value that crosses the bound is cut, the rest are dropped and the line
// is flagged truncated.
func valueFields[T int16 | uint16](key string, values [][]byte, formatCodes []T) []zap.Field {
	rendered := make(auditValues, 0, len(values))
	budget := maxAuditPayload
	truncated := false

	for i, v := range values {
		if v == nil {
			rendered = append(rendered, nil)

			continue
		}

		if len(v) > budget {
			v = v[:budget]
			truncated = true
		}

		budget -= len(v)

		s := string(v)
		if binaryFormat(formatCodes, i) {
			s = base64.StdEncoding.EncodeToString(v)
		}

		rendered = append(rendered, &s)

		if truncated {
			break
		}
	}

	fields := []zap.Field{zap.Array(key, rendered)}
	if truncated {
		fields = append(fields, zap.Bool("truncated", true))
	}

	return fields
}

// binaryFormat reports whether value i is in binary format, resolving the
// format codes as the protocol defines them: no codes means text for every
// value, one code applies to every value, otherwise each value has its own.
func binaryFormat[T int16 | uint16](codes []T, i int) bool {
	switch {
	case len(codes) == 0:
		return false
	case len(codes) == 1:
		return codes[0] == pgtype.BinaryFormatCode
	case i < len(codes):
		return codes[i] == pgtype.BinaryFormatCode
	default:
		return false
	}
}

// auditValues renders client-supplied values; a nil entry is SQL NULL and is
// emitted as JSON null so it stays distinguishable from an empty string.
type auditValues []*string

func (v auditValues) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, s := range v {
		if s == nil {
			if err := enc.AppendReflected(nil); err != nil {
				return err
			}

			continue
		}

		enc.AppendString(*s)
	}

	return nil
}

// logServerMessage accumulates response metadata from the upstream into buf
// and flushes a single `pg result` audit log on ReadyForQuery, which the
// server sends once per simple Query and once per extended-protocol Sync.
// Result sets appear in the order the statements or executes were logged.
// Row values are never recorded.
//
// ErrorResponse is captured into the buffer AND still emits an immediate
// `pg error` warn log for at-a-glance triage.
func logServerMessage(logger *zap.Logger, msg pgproto3.BackendMessage, buf *requestBuf) {
	switch m := msg.(type) {
	case *pgproto3.RowDescription:
		cols := make([]string, len(m.Fields))
		for i, f := range m.Fields {
			cols[i] = string(f.Name)
		}

		buf.results = append(buf.results, resultSet{columns: cols})

	case *pgproto3.CommandComplete:
		tag := string(m.CommandTag)
		if len(buf.results) == 0 || buf.results[len(buf.results)-1].tag != "" {
			// DML/DDL with no rowset — no RowDescription was emitted.
			buf.results = append(buf.results, resultSet{tag: tag})
		} else {
			buf.results[len(buf.results)-1].tag = tag
		}

	case *pgproto3.EmptyQueryResponse:
		buf.results = append(buf.results, resultSet{})

	case *pgproto3.ErrorResponse:
		buf.errorCode = m.Code
		buf.errorMessage = m.Message

		logger.Warn("pg error",
			zap.String("code", m.Code),
			zap.String("severity", m.Severity),
			zap.String("message", m.Message),
		)

	case *pgproto3.ReadyForQuery:
		flushRequestBuf(logger, buf)

	default:
		// DataRow, ParameterStatus, BackendKeyData, ParseComplete,
		// BindComplete, ParameterDescription, NoData, PortalSuspended,
		// CopyData, CopyOutResponse, etc. are not audit-interesting.
	}
}

// requestBuf accumulates one client request's upstream response before it
// is flushed to the audit log on ReadyForQuery.
type requestBuf struct {
	results      []resultSet
	errorCode    string
	errorMessage string
}

type resultSet struct {
	tag     string // raw PG CommandTag, e.g. "SELECT 1", "INSERT 0 3", "CREATE TABLE"
	columns []string
}

func flushRequestBuf(logger *zap.Logger, buf *requestBuf) {
	// Skip no-op flushes. PG sends its initial ReadyForQuery after the
	// post-auth greeting (ParameterStatus / BackendKeyData) — that would
	// otherwise emit an empty `pg result` log before the client has even
	// submitted a query.
	if len(buf.results) == 0 && buf.errorCode == "" && buf.errorMessage == "" {
		return
	}

	fields := []zap.Field{
		zap.Array("results", resultSetsMarshaler(buf.results)),
	}
	if buf.errorCode != "" || buf.errorMessage != "" {
		fields = append(fields,
			zap.String("error_code", buf.errorCode),
			zap.String("error_message", buf.errorMessage),
		)
	}

	logger.Info("pg result", fields...)

	buf.results = nil
	buf.errorCode = ""
	buf.errorMessage = ""
}

// resultSetsMarshaler renders the accumulated result sets as a JSON array.
type resultSetsMarshaler []resultSet

func (rs resultSetsMarshaler) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, r := range rs {
		if err := enc.AppendObject(resultSetMarshaler(r)); err != nil {
			return err
		}
	}

	return nil
}

type resultSetMarshaler resultSet

func (r resultSetMarshaler) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if r.tag != "" {
		command, rowCount, hasRowCount := parseCommandTag(r.tag)
		enc.AddString("command", command)

		if hasRowCount {
			enc.AddInt64("row_count", rowCount)
		}
	}

	if len(r.columns) > 0 {
		if err := enc.AddArray("columns", stringsMarshaler(r.columns)); err != nil {
			return err
		}
	}

	return nil
}

// parseCommandTag splits PG's CommandTag format into a command name and an
// optional row count. Examples:
//
//	"SELECT 5"        -> ("SELECT", 5, true)
//	"INSERT 0 3"      -> ("INSERT", 3, true)   // drops the legacy OID field
//	"UPDATE 2"        -> ("UPDATE", 2, true)
//	"CREATE TABLE"    -> ("CREATE TABLE", 0, false)
//	"BEGIN"           -> ("BEGIN", 0, false)
func parseCommandTag(tag string) (string, int64, bool) {
	parts := strings.Fields(tag)
	if len(parts) == 0 {
		return tag, 0, false
	}

	n, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if err != nil {
		return tag, 0, false
	}

	// INSERT's legacy "oid" slot sits between the command and the row count;
	// always 0 in modern PG. Drop it so the command field reads as "INSERT".
	commandParts := parts[:len(parts)-1]
	if len(commandParts) >= 2 && strings.EqualFold(commandParts[0], "INSERT") {
		commandParts = commandParts[:1]
	}

	return strings.Join(commandParts, " "), n, true
}

type stringsMarshaler []string

func (s stringsMarshaler) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, v := range s {
		enc.AppendString(v)
	}

	return nil
}

// Closed sockets, EOF, and context cancellation during steady-state are normal
// terminations, not errors worth surfacing. ErrUnexpectedEOF lands here too
// because pgproto3's chunkReader may be mid-read when we close the sockets in
// response to a client Terminate on the sibling goroutine.
func isBenignRelayErr(err error) bool {
	if err == nil {
		return true
	}

	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled)
}
