// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestLogClientMessage(t *testing.T) {
	longSQL := "SELECT '" + strings.Repeat("a", maxAuditPayload) + "'"

	tests := []struct {
		name        string
		msg         pgproto3.FrontendMessage
		wantMessage string
		wantFields  map[string]any
	}{
		{
			name:        "simple query",
			msg:         &pgproto3.Query{String: "SELECT 1"},
			wantMessage: "pg query",
			wantFields:  map[string]any{"sql": "SELECT 1"},
		},
		{
			name:        "simple query over the cap is cut and flagged",
			msg:         &pgproto3.Query{String: longSQL},
			wantMessage: "pg query",
			wantFields:  map[string]any{"sql": longSQL[:maxAuditPayload], "truncated": true},
		},
		{
			name:        "parse",
			msg:         &pgproto3.Parse{Name: "stmt1", Query: "SELECT $1"},
			wantMessage: "pg parse",
			wantFields:  map[string]any{"name": "stmt1", "sql": "SELECT $1"},
		},
		{
			name: "bind with no format codes logs text and NULL",
			msg: &pgproto3.Bind{
				PreparedStatement: "stmt1",
				DestinationPortal: "",
				Parameters:        [][]byte{[]byte("42"), nil, []byte("alice")},
			},
			wantMessage: "pg bind",
			wantFields: map[string]any{
				"statement":  "stmt1",
				"portal":     "",
				"parameters": []any{"42", nil, "alice"},
			},
		},
		{
			name: "bind with one format code applies it to every parameter",
			msg: &pgproto3.Bind{
				ParameterFormatCodes: []int16{1},
				Parameters:           [][]byte{{0x00, 0x2a}, {0xff}},
			},
			wantMessage: "pg bind",
			wantFields: map[string]any{
				"statement":  "",
				"portal":     "",
				"parameters": []any{"ACo=", "/w=="},
			},
		},
		{
			name: "bind with per-parameter format codes",
			msg: &pgproto3.Bind{
				ParameterFormatCodes: []int16{0, 1},
				Parameters:           [][]byte{[]byte("text"), {0x00, 0x2a}},
			},
			wantMessage: "pg bind",
			wantFields: map[string]any{
				"statement":  "",
				"portal":     "",
				"parameters": []any{"text", "ACo="},
			},
		},
		{
			name: "bind over the cap cuts the crossing value and drops the rest",
			msg: &pgproto3.Bind{
				Parameters: [][]byte{
					[]byte(strings.Repeat("a", maxAuditPayload-1)),
					[]byte("xyz"),
					[]byte("dropped"),
				},
			},
			wantMessage: "pg bind",
			wantFields: map[string]any{
				"statement":  "",
				"portal":     "",
				"parameters": []any{strings.Repeat("a", maxAuditPayload-1), "x"},
				"truncated":  true,
			},
		},
		{
			name:        "execute",
			msg:         &pgproto3.Execute{Portal: "p1", MaxRows: 50},
			wantMessage: "pg execute",
			wantFields:  map[string]any{"portal": "p1", "max_rows": uint32(50)},
		},
		{
			name: "function call",
			msg: &pgproto3.FunctionCall{
				Function:       952,
				ArgFormatCodes: []uint16{1, 1},
				Arguments:      [][]byte{{0x00, 0x00, 0x40, 0x01}, {0x00, 0x00, 0x00, 0x00}},
			},
			wantMessage: "pg function_call",
			wantFields: map[string]any{
				"function":  uint32(952),
				"arguments": []any{"AABAAQ==", "AAAAAA=="},
			},
		},
		{
			name: "describe is not logged",
			msg:  &pgproto3.Describe{ObjectType: 'S', Name: "stmt1"},
		},
		{
			name: "sync is not logged",
			msg:  &pgproto3.Sync{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.InfoLevel)

			logClientMessage(zap.New(core), tt.msg)

			if tt.wantMessage == "" {
				assert.Zero(t, logs.Len())

				return
			}

			entries := logs.All()
			require.Len(t, entries, 1)
			assert.Equal(t, tt.wantMessage, entries[0].Message)
			assert.Equal(t, tt.wantFields, entries[0].ContextMap())
		})
	}
}

func TestLogServerMessage(t *testing.T) {
	idColumn := &pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("id")}}}

	tests := []struct {
		name       string
		msgs       []pgproto3.BackendMessage
		wantResult map[string]any // nil means no pg result line
		wantError  bool
	}{
		{
			name: "initial ReadyForQuery logs nothing",
			msgs: []pgproto3.BackendMessage{&pgproto3.ReadyForQuery{TxStatus: 'I'}},
		},
		{
			name: "describe round logs columns without a command",
			msgs: []pgproto3.BackendMessage{
				&pgproto3.ParseComplete{},
				&pgproto3.ParameterDescription{},
				idColumn,
				&pgproto3.ReadyForQuery{TxStatus: 'I'},
			},
			wantResult: map[string]any{
				"results": []any{map[string]any{"columns": []any{"id"}}},
			},
		},
		{
			name: "select logs command, row count and columns but no rows",
			msgs: []pgproto3.BackendMessage{
				idColumn,
				&pgproto3.DataRow{Values: [][]byte{[]byte("1")}},
				&pgproto3.DataRow{Values: [][]byte{[]byte("2")}},
				&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
				&pgproto3.ReadyForQuery{TxStatus: 'I'},
			},
			wantResult: map[string]any{
				"results": []any{map[string]any{
					"command":   "SELECT",
					"row_count": int64(2),
					"columns":   []any{"id"},
				}},
			},
		},
		{
			name: "execute without describe logs command only",
			msgs: []pgproto3.BackendMessage{
				&pgproto3.BindComplete{},
				&pgproto3.DataRow{Values: [][]byte{[]byte("1")}},
				&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
				&pgproto3.ReadyForQuery{TxStatus: 'I'},
			},
			wantResult: map[string]any{
				"results": []any{map[string]any{"command": "SELECT", "row_count": int64(1)}},
			},
		},
		{
			name: "multi-statement query keeps result sets in order",
			msgs: []pgproto3.BackendMessage{
				&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")},
				idColumn,
				&pgproto3.CommandComplete{CommandTag: []byte("SELECT 0")},
				&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 3")},
				&pgproto3.CommandComplete{CommandTag: []byte("COMMIT")},
				&pgproto3.ReadyForQuery{TxStatus: 'I'},
			},
			wantResult: map[string]any{
				"results": []any{
					map[string]any{"command": "BEGIN"},
					map[string]any{"command": "SELECT", "row_count": int64(0), "columns": []any{"id"}},
					map[string]any{"command": "INSERT", "row_count": int64(3)},
					map[string]any{"command": "COMMIT"},
				},
			},
		},
		{
			name: "empty query",
			msgs: []pgproto3.BackendMessage{
				&pgproto3.EmptyQueryResponse{},
				&pgproto3.ReadyForQuery{TxStatus: 'I'},
			},
			wantResult: map[string]any{"results": []any{map[string]any{}}},
		},
		{
			name: "error mid-batch keeps completed sets and records the error",
			msgs: []pgproto3.BackendMessage{
				&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 1")},
				&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42P01", Message: "relation does not exist"},
				&pgproto3.ReadyForQuery{TxStatus: 'E'},
			},
			wantResult: map[string]any{
				"results":       []any{map[string]any{"command": "INSERT", "row_count": int64(1)}},
				"error_code":    "42P01",
				"error_message": "relation does not exist",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.InfoLevel)
			logger := zap.New(core)
			buf := &requestBuf{}

			for _, msg := range tt.msgs {
				logServerMessage(logger, msg, buf)
			}

			results := logs.FilterMessage("pg result").All()
			if tt.wantResult == nil {
				assert.Empty(t, results)
			} else {
				require.Len(t, results, 1)
				assert.Equal(t, tt.wantResult, results[0].ContextMap())
			}

			errs := logs.FilterMessage("pg error").All()
			if tt.wantError {
				assert.Len(t, errs, 1)
			} else {
				assert.Empty(t, errs)
			}

			// The buffer is reset after each flush so the next request starts clean.
			assert.Equal(t, &requestBuf{}, buf)
		})
	}
}

func TestParseCommandTag(t *testing.T) {
	tests := []struct {
		name        string
		tag         string
		wantCommand string
		wantRows    int64
		wantHasRows bool
	}{
		{
			name:        "SELECT with row count",
			tag:         "SELECT 5",
			wantCommand: "SELECT",
			wantRows:    5,
			wantHasRows: true,
		},
		{
			name:        "INSERT drops oid",
			tag:         "INSERT 0 3",
			wantCommand: "INSERT",
			wantRows:    3,
			wantHasRows: true,
		},
		{
			name:        "UPDATE",
			tag:         "UPDATE 2",
			wantCommand: "UPDATE",
			wantRows:    2,
			wantHasRows: true,
		},
		{
			name:        "DELETE",
			tag:         "DELETE 1",
			wantCommand: "DELETE",
			wantRows:    1,
			wantHasRows: true,
		},
		{
			name:        "CREATE TABLE has no row count",
			tag:         "CREATE TABLE",
			wantCommand: "CREATE TABLE",
			wantRows:    0,
			wantHasRows: false,
		},
		{
			name:        "BEGIN has no row count",
			tag:         "BEGIN",
			wantCommand: "BEGIN",
			wantRows:    0,
			wantHasRows: false,
		},
		{
			name:        "zero-row SELECT",
			tag:         "SELECT 0",
			wantCommand: "SELECT",
			wantRows:    0,
			wantHasRows: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command, rows, hasRows := parseCommandTag(tt.tag)
			assert.Equal(t, tt.wantCommand, command)
			assert.Equal(t, tt.wantRows, rows)
			assert.Equal(t, tt.wantHasRows, hasRows)
		})
	}
}
