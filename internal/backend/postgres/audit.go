// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"encoding/base64"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Audit log field names.
const (
	fieldRequestID     = "request_id"
	fieldDurationMS    = "duration_ms"
	fieldSQL           = "sql"
	fieldStatementName = "statement_name"
	fieldPortalName    = "portal_name"
	fieldTruncated     = "truncated"
)

// maxAuditValueBytes caps the SQL text, the error message, or the combined parameter bytes of one
// audit line.
const maxAuditValueBytes = 64 * humanize.KiByte

// Object types that Describe and Close messages name.
const (
	objectTypeStatement = 'S'
	objectTypePortal    = 'P'
)

// txStatusIdle is the ReadyForQuery status of a connection outside any transaction.
const txStatusIdle = 'I'

// auditObserver writes one audit line per client message and per statement result. A request is
// everything between two ReadyForQuery messages: any client message starts one request,
// and the server's ReadyForQuery closes it.
//
// Drivers (for e.g., pgx) with a statement cache describe a statement once and later only bind
// and execute it, so the columns of each described statement are kept until it is closed or
// parsed again.
type auditObserver struct {
	logger *zap.Logger

	// mu guards the fields below, which both directions of the relay read and write.
	mu sync.Mutex

	requestID uint64
	startedAt time.Time
	columns   []string

	// statements maps each described prepared statement to its column names. Entries last for the
	// connection, as the server's own statements do, so a later Execute can find the columns of the
	// statement it runs.
	statements map[string][]string
	// portals maps each portal to the statement it was bound from, so an Execute can find
	// the statement and its columns. Entries end with a Close or with the transaction, as the
	// server's own portals do.
	portals map[string]string
	// Store Describes and Executes the server has not answered yet. It answers them in the order the
	// client sent them, so the oldest one is the one each answer belongs to.
	describes queue[describe]
	executes  queue[string]
}

type describe struct {
	objectType byte
	name       string
}

type queue[T any] []T

func (q *queue[T]) enqueue(value T) {
	*q = append(*q, value)
}

// dequeue reports false when the queue is empty.
func (q *queue[T]) dequeue() (T, bool) {
	if len(*q) == 0 {
		var zero T

		return zero, false
	}

	value := (*q)[0]
	*q = (*q)[1:]

	return value, true
}

func newAuditObserver(logger *zap.Logger) *auditObserver {
	return &auditObserver{logger: logger, statements: map[string][]string{}, portals: map[string]string{}}
}

func (o *auditObserver) onDownstreamMessage(msg pgproto3.FrontendMessage) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.startedAt.IsZero() {
		o.requestID++
		o.startedAt = time.Now()
	}

	fields := []zap.Field{zap.Uint64(fieldRequestID, o.requestID)}

	switch msg := msg.(type) {
	case *pgproto3.Query:
		o.logger.Info("pg query", append(fields, stringFields(fieldSQL, msg.String)...)...)
	case *pgproto3.Parse:
		delete(o.statements, msg.Name)

		fields = slices.Concat(fields, []zap.Field{
			zap.String(fieldStatementName, msg.Name),
		}, stringFields(fieldSQL, msg.Query))

		o.logger.Info("pg parse", fields...)
	case *pgproto3.Bind:
		o.portals[msg.DestinationPortal] = msg.PreparedStatement

		fields = slices.Concat(fields, []zap.Field{
			zap.String(fieldStatementName, msg.PreparedStatement),
			zap.String(fieldPortalName, msg.DestinationPortal),
		}, valueFields("parameters", msg.ParameterFormatCodes, msg.Parameters))

		o.logger.Info("pg bind", fields...)
	case *pgproto3.Describe:
		o.describes.enqueue(describe{objectType: msg.ObjectType, name: msg.Name})
	case *pgproto3.Execute:
		o.executes.enqueue(o.portals[msg.Portal])

		fields = append(fields, zap.String(fieldPortalName, msg.Portal), zap.Uint32("max_rows", msg.MaxRows))

		o.logger.Info("pg execute", fields...)
	case *pgproto3.FunctionCall:
		fields = slices.Concat(fields, []zap.Field{
			zap.Uint32("function", msg.Function),
		}, valueFields("arguments", msg.ArgFormatCodes, msg.Arguments))

		o.logger.Info("pg function_call", fields...)
	case *pgproto3.Close:
		switch msg.ObjectType {
		case objectTypeStatement:
			delete(o.statements, msg.Name)
		case objectTypePortal:
			delete(o.portals, msg.Name)
		default:
			// The server rejects any other object type.
		}
	default:
		// Sync, Flush, Terminate and COPY data (CopyData, CopyDone, CopyFail) carry no statement to
		// audit, and COPY data is never logged.
	}
}

func (o *auditObserver) onUpstreamMessage(msg pgproto3.BackendMessage) {
	o.mu.Lock()
	defer o.mu.Unlock()

	switch msg := msg.(type) {
	case *pgproto3.RowDescription:
		columns := make([]string, len(msg.Fields))
		for i, field := range msg.Fields {
			columns[i] = string(field.Name)
		}

		if statement, ok := o.describedStatement(); ok {
			o.statements[statement] = columns
		} else {
			o.columns = columns
		}
	case *pgproto3.NoData:
		if statement, ok := o.describedStatement(); ok {
			o.statements[statement] = nil
		}
	case *pgproto3.CommandComplete:
		command, rowCount, hasRowCount := parseCommandTag(msg.CommandTag)
		fields := []zap.Field{zap.String("command", command)}

		if hasRowCount {
			fields = append(fields, zap.Int64("row_count", rowCount))
		}

		if columns := o.nextResultColumns(); columns != nil {
			fields = append(fields, zap.Strings("columns", columns))
		}

		o.logResult(fields...)
	case *pgproto3.EmptyQueryResponse:
		o.nextResultColumns()
		o.logResult()
	case *pgproto3.PortalSuspended:
		// A suspended portal has no command tag to log. The CommandComplete that ends the portal
		// counts only its last batch, so the row_count of a cursor is the last fetch.
		o.nextResultColumns()
	case *pgproto3.ErrorResponse:
		fields := slices.Concat([]zap.Field{
			zap.String("error_code", msg.Code)},
			stringFields("error_message", msg.Message),
		)

		o.logResult(fields...)
	case *pgproto3.ReadyForQuery:
		if !o.startedAt.IsZero() {
			o.logger.Info("pg completed", o.requestFields()...)
		}

		// The server drops every portal when its transaction ends.
		if msg.TxStatus == txStatusIdle {
			clear(o.portals)
		}

		o.reset()
	default:
		// DataRow and COPY data are never logged due to privacy and volume reasons. The rest (ParseComplete,
		// BindComplete, CloseComplete, ParameterDescription, CopyInResponse, CopyOutResponse,
		// FunctionCallResponse, NoticeResponse, NotificationResponse, ParameterStatus) say nothing
		// about the statement's outcome.
	}
}

// reset closes the request, so nothing pending carries over to the next request.
func (o *auditObserver) reset() {
	o.startedAt = time.Time{}
	o.columns = nil
	o.describes = nil
	o.executes = nil
}

// describedStatement consumes the oldest unanswered Describe, and returns the statement name with
// true only when that Describe targeted a prepared statement.
func (o *auditObserver) describedStatement() (string, bool) {
	target, ok := o.describes.dequeue()
	if !ok {
		return "", false
	}

	return target.name, target.objectType == objectTypeStatement
}

// nextResultColumns consumes the oldest unanswered Execute, because every result answers one.
func (o *auditObserver) nextResultColumns() []string {
	statement, ok := o.executes.dequeue()
	if !ok {
		return o.columns
	}

	if o.columns != nil {
		return o.columns
	}

	return o.statements[statement]
}

func (o *auditObserver) logResult(fields ...zap.Field) {
	o.logger.Info("pg result", append(o.requestFields(), fields...)...)

	// The RowDescription that set these columns described this result only. Clearing them keeps the
	// next result in the same request, such as the INSERT in "SELECT 1; INSERT ...", from being
	// logged with the SELECT's columns.
	o.columns = nil
}

// requestFields is empty when no request is open: a server message that arrives between a
// ReadyForQuery and the client's next message belongs to no request.
func (o *auditObserver) requestFields() []zap.Field {
	if o.startedAt.IsZero() {
		return nil
	}

	return []zap.Field{
		zap.Uint64(fieldRequestID, o.requestID),
		zap.Int64(fieldDurationMS, time.Since(o.startedAt).Milliseconds()),
	}
}

func stringFields(name, value string) []zap.Field {
	value, truncated := truncate(value, maxAuditValueBytes)
	if truncated {
		return []zap.Field{zap.String(name, value), zap.Bool(fieldTruncated, true)}
	}

	return []zap.Field{zap.String(name, value)}
}

// valueFields builds the parameters of a `pg bind` line and the arguments of a `pg function_call` line,
// cutting the value that crosses the audit size cap and dropping the values after it.
func valueFields[F int16 | uint16](name string, formatCodes []F, values [][]byte) []zap.Field {
	logged := make([]any, 0, len(values))
	remaining := maxAuditValueBytes
	truncated := false

	for i, value := range values {
		if truncated {
			break
		}

		// A value that meets an empty remaining cap is dropped rather than logged as an empty value.
		if remaining == 0 && len(value) > 0 {
			truncated = true

			break
		}

		if value == nil {
			logged = append(logged, nil)

			continue
		}

		value, truncated = truncate(value, remaining)
		remaining -= len(value)

		if isBinaryFormat(formatCodes, i) {
			// Binary value logged as base64
			logged = append(logged, base64.StdEncoding.EncodeToString(value))
		} else {
			logged = append(logged, string(value))
		}
	}

	if truncated {
		return []zap.Field{zap.Any(name, logged), zap.Bool(fieldTruncated, true)}
	}

	return []zap.Field{zap.Any(name, logged)}
}

// parseCommandTag splits a tag such as "SELECT 2", "INSERT 0 5" or "CREATE TABLE" into its command
// and row count. A tag without a count, such as "BEGIN", is returned whole as the command.
func parseCommandTag(tag []byte) (command string, rowCount int64, hasRowCount bool) {
	words := strings.Fields(string(tag))
	if len(words) == 0 {
		return string(tag), 0, false
	}

	rowCount, err := strconv.ParseInt(words[len(words)-1], 10, 64)
	if err != nil {
		return string(tag), 0, false
	}

	return words[0], rowCount, true
}

func truncate[T string | []byte](value T, size int) (T, bool) {
	if len(value) <= size {
		return value, false
	}

	return value[:size], true
}

func isBinaryFormat[F int16 | uint16](formatCodes []F, i int) bool {
	switch len(formatCodes) {
	case 0:
		// No format code means every value is text.
		return false
	case 1:
		// A single format code applies to every value.
		return formatCodes[0] == pgtype.BinaryFormatCode
	default:
		// A value with out-of-range index format code is logged as text.
		return i < len(formatCodes) && formatCodes[i] == pgtype.BinaryFormatCode
	}
}
