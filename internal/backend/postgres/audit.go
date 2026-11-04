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

// maxAuditValueBytes caps the SQL text, the error message, or the combined parameters of one audit line.
const maxAuditValueBytes = 64 * humanize.KiByte

// auditObserver writes one audit line per client message and per statement result. A request is
// what the client sends up to a Sync, a simple Query or a FunctionCall. The server answers each
// request with one ReadyForQuery, in the order the requests were sent, even when the request
// failed. A client may send more requests before the first is answered (pipelining).
type auditObserver struct {
	logger *zap.Logger

	// mu guards the fields below, which both directions of the relay read and write.
	mu sync.Mutex

	requestID uint64

	// requests is a FIFO queue of the requests the server has not answered. Client messages join
	// the newest request at the tail, and each ReadyForQuery removes the oldest from the head.
	requests []*request
	// startNew gates the tail: once a message ends the newest request, the next message appends a
	// new one.
	startNew bool
}

// request takes a number at its first audited message. A request without one, such as a lone
// Sync, still waits for its ReadyForQuery but is not logged.
type request struct {
	id        uint64
	startedAt time.Time

	// copying is set while the server waits for this request's COPY data. PostgreSQL ignores a Sync
	// it reads then, so the request stays open until the client's CopyDone or CopyFail.
	copying bool
}

func newAuditObserver(logger *zap.Logger) *auditObserver {
	return &auditObserver{logger: logger}
}

func (o *auditObserver) onDownstreamMessage(msg pgproto3.FrontendMessage) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if len(o.requests) == 0 || o.startNew {
		o.requests = append(o.requests, &request{})
		o.startNew = false
	}

	r := o.requests[len(o.requests)-1]

	if shouldStartAudit(r, msg) {
		o.requestID++
		r.id = o.requestID
		r.startedAt = time.Now()
	}

	fields := []zap.Field{zap.Uint64(fieldRequestID, r.id)}

	switch msg := msg.(type) {
	case *pgproto3.Query:
		o.logger.Info("pg query", append(fields, stringFields(fieldSQL, msg.String)...)...)
	case *pgproto3.Parse:
		fields = slices.Concat(fields, []zap.Field{
			zap.String(fieldStatementName, msg.Name),
		}, stringFields(fieldSQL, msg.Query))

		o.logger.Info("pg parse", fields...)
	case *pgproto3.Bind:
		fields = slices.Concat(fields, []zap.Field{
			zap.String(fieldStatementName, msg.PreparedStatement),
			zap.String(fieldPortalName, msg.DestinationPortal),
		}, valueFields("parameters", msg.ParameterFormatCodes, msg.Parameters))

		o.logger.Info("pg bind", fields...)
	case *pgproto3.Execute:
		fields = append(fields, zap.String(fieldPortalName, msg.Portal), zap.Uint32("max_rows", msg.MaxRows))

		o.logger.Info("pg execute", fields...)
	case *pgproto3.FunctionCall:
		fields = slices.Concat(fields, []zap.Field{
			zap.Uint32("function", msg.Function),
		}, valueFields("arguments", msg.ArgFormatCodes, msg.Arguments))

		o.logger.Info("pg function_call", fields...)
	case *pgproto3.CopyDone, *pgproto3.CopyFail:
		// They end the COPY, like CopyData, they are not audited.
		r.copying = false
	default:
		// Describe, Close, Sync, Flush, Terminate and CopyData are not audited.
	}

	o.startNew = shouldStartNew(r, msg)
}

func (o *auditObserver) onUpstreamMessage(msg pgproto3.BackendMessage) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// The server answers requests in the order they were sent, so its message belongs to the
	// oldest request still waiting.
	var r *request
	if len(o.requests) > 0 {
		r = o.requests[0]
	}

	switch msg := msg.(type) {
	case *pgproto3.CommandComplete:
		command, rowCount, hasRowCount := parseCommandTag(msg.CommandTag)
		fields := append(r.fields(), zap.String("command", command))

		if hasRowCount {
			fields = append(fields, zap.Int64("row_count", rowCount))
		}

		o.logger.Info("pg result", fields...)
	case *pgproto3.EmptyQueryResponse, *pgproto3.FunctionCallResponse:
		o.logger.Info("pg result", r.fields()...)
	case *pgproto3.PortalSuspended:
		// The Execute stopped at its max_rows; the portal's next Execute continues the same result.
		o.logger.Info("pg result", append(r.fields(), zap.Bool("suspended", true))...)
	case *pgproto3.ErrorResponse:
		fields := slices.Concat(r.fields(), []zap.Field{
			zap.String("error_code", msg.Code)},
			stringFields("error_message", msg.Message),
		)

		o.logger.Info("pg result", fields...)
	case *pgproto3.CopyInResponse:
		// The request stays open until the client ends the COPY, even if the client already sent a
		// Sync after the Execute: the server ignores that Sync.
		if r != nil {
			r.copying = true
			o.startNew = false
		}
	case *pgproto3.ReadyForQuery:
		if r == nil {
			break
		}

		// The backing array would otherwise keep the answered request alive.
		o.requests[0] = nil
		o.requests = o.requests[1:]

		if !r.startedAt.IsZero() {
			o.logger.Info("pg completed", r.fields()...)
		}
	default:
		// DataRow and COPY data are never logged due to privacy and volume reasons. The rest
		// (ParseComplete, BindComplete, CloseComplete, ParameterDescription, RowDescription, NoData,
		// CopyOutResponse, NoticeResponse, NotificationResponse, ParameterStatus)
		// are ignored.
	}
}

// fields is empty when a server message belongs to no numbered request: it arrived with no
// request waiting, or its request has no audited message.
func (r *request) fields() []zap.Field {
	if r == nil || r.startedAt.IsZero() {
		return nil
	}

	return []zap.Field{
		zap.Uint64(fieldRequestID, r.id),
		zap.Int64(fieldDurationMS, time.Since(r.startedAt).Milliseconds()),
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

		if value == nil {
			logged = append(logged, nil)

			continue
		}

		binary := isBinaryFormat(formatCodes, i)

		limit := remaining
		if binary {
			// base64 writes 4 bytes for every 3, so fewer raw bytes fit.
			limit = remaining / 4 * 3
		}

		// A value that meets an empty remaining cap is dropped rather than logged as an empty value.
		if limit == 0 && len(value) > 0 {
			truncated = true

			break
		}

		value, truncated = truncate(value, limit)

		if binary {
			encoded := base64.StdEncoding.EncodeToString(value)
			remaining -= len(encoded)
			logged = append(logged, encoded)
		} else {
			remaining -= len(value)
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

func shouldStartAudit(r *request, msg pgproto3.FrontendMessage) bool {
	if !r.startedAt.IsZero() {
		return false
	}

	switch msg.(type) {
	case *pgproto3.Query, *pgproto3.Parse, *pgproto3.Bind, *pgproto3.Execute, *pgproto3.FunctionCall:
		return true
	default:
		return false
	}
}

// shouldStartNew reports whether the server answers msg with a ReadyForQuery, so the client's next
// message starts a new request.
func shouldStartNew(r *request, msg pgproto3.FrontendMessage) bool {
	if r.copying {
		return false
	}

	switch msg.(type) {
	case *pgproto3.Query, *pgproto3.Sync, *pgproto3.FunctionCall:
		return true
	default:
		return false
	}
}
