// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"encoding/base64"
	"slices"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Audit log field names.
const (
	fieldSQL           = "sql"
	fieldStatementName = "statement_name"
	fieldPortalName    = "portal_name"
	fieldTruncated     = "truncated"
)

// maxAuditValueBytes caps the SQL text, the error message, or the combined parameters of one audit line.
const maxAuditValueBytes = 64 * humanize.KiByte

// auditObserver writes one audit line per client message and per statement result, as the relay
// sees each one.
type auditObserver struct {
	logger *zap.Logger
}

func newAuditObserver(logger *zap.Logger) *auditObserver {
	return &auditObserver{logger: logger}
}

func (o *auditObserver) onDownstreamMessage(msg pgproto3.FrontendMessage) {
	switch msg := msg.(type) {
	case *pgproto3.Query:
		o.logger.Info("pg query", stringFields(fieldSQL, msg.String)...)
	case *pgproto3.Parse:
		fields := slices.Concat([]zap.Field{
			zap.String(fieldStatementName, msg.Name),
		}, stringFields(fieldSQL, msg.Query))

		o.logger.Info("pg parse", fields...)
	case *pgproto3.Bind:
		fields := slices.Concat([]zap.Field{
			zap.String(fieldStatementName, msg.PreparedStatement),
			zap.String(fieldPortalName, msg.DestinationPortal),
		}, valueFields("parameters", msg.ParameterFormatCodes, msg.Parameters))

		o.logger.Info("pg bind", fields...)
	case *pgproto3.Execute:
		o.logger.Info("pg execute", zap.String(fieldPortalName, msg.Portal), zap.Uint32("max_rows", msg.MaxRows))
	case *pgproto3.FunctionCall:
		fields := slices.Concat([]zap.Field{
			zap.Uint32("function", msg.Function),
		}, valueFields("arguments", msg.ArgFormatCodes, msg.Arguments))

		o.logger.Info("pg function_call", fields...)
	default:
		// Describe, Close, Sync, Flush, Terminate and the COPY messages are not audited.
	}
}

func (o *auditObserver) onUpstreamMessage(msg pgproto3.BackendMessage) {
	switch msg := msg.(type) {
	case *pgproto3.CommandComplete:
		command, rowCount, hasRowCount := parseCommandTag(msg.CommandTag)
		fields := []zap.Field{zap.String("command", command)}

		if hasRowCount {
			fields = append(fields, zap.Int64("row_count", rowCount))
		}

		o.logger.Info("pg result", fields...)
	case *pgproto3.EmptyQueryResponse, *pgproto3.FunctionCallResponse:
		o.logger.Info("pg result")
	case *pgproto3.ErrorResponse:
		fields := slices.Concat([]zap.Field{
			zap.String("error_code", msg.Code),
		}, stringFields("error_message", msg.Message))

		o.logger.Info("pg result", fields...)
	default:
		// DataRow and COPY data are never logged due to privacy and volume reasons. The rest
		// (ParseComplete, BindComplete, CloseComplete, ParameterDescription, RowDescription, NoData,
		// PortalSuspended, CopyInResponse, CopyOutResponse, NoticeResponse, NotificationResponse,
		// ParameterStatus, ReadyForQuery) are ignored.
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
