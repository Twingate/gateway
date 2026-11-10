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

// maxAuditValueBytes caps each statement name, portal name, SQL text and error message in an audit
// line, and the combined parameters of one line.
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
		sql, truncated := stringField(fieldSQL, msg.String)

		o.logger.Info("pg query", sql, truncatedField(truncated))
	case *pgproto3.Parse:
		statement, statementTruncated := stringField(fieldStatementName, msg.Name)
		sql, sqlTruncated := stringField(fieldSQL, msg.Query)

		o.logger.Info("pg parse", statement, sql, truncatedField(statementTruncated, sqlTruncated))
	case *pgproto3.Bind:
		statement, statementTruncated := stringField(fieldStatementName, msg.PreparedStatement)
		portal, portalTruncated := stringField(fieldPortalName, msg.DestinationPortal)
		parameters, parametersTruncated := valueField("parameters", msg.ParameterFormatCodes, msg.Parameters)

		o.logger.Info("pg bind", statement, portal, parameters,
			truncatedField(statementTruncated, portalTruncated, parametersTruncated))
	case *pgproto3.Execute:
		portal, truncated := stringField(fieldPortalName, msg.Portal)

		o.logger.Info("pg execute", portal, zap.Uint32("max_rows", msg.MaxRows), truncatedField(truncated))
	case *pgproto3.FunctionCall:
		arguments, truncated := valueField("arguments", msg.ArgFormatCodes, msg.Arguments)

		o.logger.Info("pg function_call", zap.Uint32("function", msg.Function), arguments, truncatedField(truncated))
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
		message, truncated := stringField("error_message", msg.Message)

		o.logger.Info("pg result", zap.String("error_code", msg.Code), message, truncatedField(truncated))
	case *pgproto3.PortalSuspended:
		o.logger.Info("pg result", zap.Bool("suspended", true))
	case *pgproto3.ReadyForQuery:
		o.logger.Info("pg completed")
	default:
		// DataRow and COPY data are never logged due to privacy and volume reasons. The rest
		// (ParseComplete, BindComplete, CloseComplete, ParameterDescription, RowDescription, NoData,
		// CopyInResponse, CopyOutResponse, NoticeResponse, NotificationResponse, ParameterStatus)
		// are ignored.
	}
}

func stringField(name, value string) (zap.Field, bool) {
	value, truncated := truncate(value, maxAuditValueBytes)

	return zap.String(name, value), truncated
}

// truncatedField writes a single truncated field for a line when any of its values was cut.
func truncatedField(truncated ...bool) zap.Field {
	if slices.Contains(truncated, true) {
		return zap.Bool(fieldTruncated, true)
	}

	return zap.Skip()
}

// valueField builds the parameters of a `pg bind` line and the arguments of a `pg function_call` line,
// cutting the value that crosses the audit size cap and dropping the values after it.
func valueField[F int16 | uint16](name string, formatCodes []F, values [][]byte) (zap.Field, bool) {
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

	return zap.Any(name, logged), truncated
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
