// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	zapobserver "go.uber.org/zap/zaptest/observer"
)

type auditLine struct {
	message string
	fields  map[string]any
}

// takeLines returns the auditLine written since the last call.
func takeLines(logs *zapobserver.ObservedLogs) []auditLine {
	lines := []auditLine{}

	for _, entry := range logs.TakeAll() {
		lines = append(lines, auditLine{message: entry.Message, fields: entry.ContextMap()})
	}

	return lines
}

func TestAuditObserver_ClientMessages(t *testing.T) {
	overCap := strings.Repeat("s", maxAuditValueBytes+1)
	atCap := overCap[:maxAuditValueBytes]

	tests := []struct {
		name string
		msgs []pgproto3.FrontendMessage
		want []auditLine
	}{
		{
			name: "query",
			msgs: []pgproto3.FrontendMessage{&pgproto3.Query{String: "SELECT 1"}},
			want: []auditLine{{"pg query", map[string]any{"sql": "SELECT 1"}}},
		},
		{
			name: "query over the cap",
			msgs: []pgproto3.FrontendMessage{&pgproto3.Query{String: overCap}},
			want: []auditLine{{"pg query", map[string]any{"sql": atCap, "truncated": true}}},
		},
		{
			name: "parse",
			msgs: []pgproto3.FrontendMessage{&pgproto3.Parse{Name: "stmtcache_3", Query: "SELECT $1"}},
			want: []auditLine{{"pg parse", map[string]any{"statement_name": "stmtcache_3", "sql": "SELECT $1"}}},
		},
		{
			name: "parse with a statement name over the cap",
			msgs: []pgproto3.FrontendMessage{&pgproto3.Parse{Name: overCap, Query: "SELECT 1"}},
			want: []auditLine{{"pg parse", map[string]any{"statement_name": atCap, "sql": "SELECT 1", "truncated": true}}},
		},
		{
			name: "bind",
			msgs: []pgproto3.FrontendMessage{&pgproto3.Bind{PreparedStatement: "stmtcache_3", Parameters: [][]byte{[]byte("42")}}},
			want: []auditLine{{"pg bind", map[string]any{
				"statement_name": "stmtcache_3", "portal_name": "", "parameters": []any{"42"},
			}}},
		},
		{
			name: "bind with names over the cap",
			msgs: []pgproto3.FrontendMessage{&pgproto3.Bind{PreparedStatement: overCap, DestinationPortal: overCap}},
			want: []auditLine{{"pg bind", map[string]any{
				"statement_name": atCap, "portal_name": atCap, "parameters": []any{}, "truncated": true,
			}}},
		},
		{
			name: "bind with parameters over the cap",
			msgs: []pgproto3.FrontendMessage{&pgproto3.Bind{PreparedStatement: "stmtcache_3", Parameters: [][]byte{[]byte(overCap)}}},
			want: []auditLine{{"pg bind", map[string]any{
				"statement_name": "stmtcache_3", "portal_name": "", "parameters": []any{atCap}, "truncated": true,
			}}},
		},
		{
			name: "execute",
			msgs: []pgproto3.FrontendMessage{&pgproto3.Execute{Portal: "p1", MaxRows: 10}},
			want: []auditLine{{"pg execute", map[string]any{"portal_name": "p1", "max_rows": uint32(10)}}},
		},
		{
			name: "execute with a portal name over the cap",
			msgs: []pgproto3.FrontendMessage{&pgproto3.Execute{Portal: overCap}},
			want: []auditLine{{"pg execute", map[string]any{"portal_name": atCap, "max_rows": uint32(0), "truncated": true}}},
		},
		{
			name: "function call",
			msgs: []pgproto3.FrontendMessage{
				&pgproto3.FunctionCall{Function: 1234, ArgFormatCodes: []uint16{pgtype.BinaryFormatCode}, Arguments: [][]byte{{1}}},
			},
			want: []auditLine{{"pg function_call", map[string]any{
				"function": uint32(1234), "arguments": []any{"AQ=="},
			}}},
		},
		{
			name: "never logged",
			msgs: []pgproto3.FrontendMessage{
				&pgproto3.Describe{ObjectType: 'S', Name: "s1"},
				&pgproto3.Close{ObjectType: 'S', Name: "s1"}, &pgproto3.Close{ObjectType: 'P', Name: "p1"},
				&pgproto3.Sync{}, &pgproto3.Flush{},
				&pgproto3.CopyData{Data: []byte("1\tone\n")}, &pgproto3.CopyDone{}, &pgproto3.CopyFail{Message: "aborted"},
				&pgproto3.Terminate{},
			},
			want: []auditLine{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := zapobserver.New(zap.InfoLevel)
			o := newAuditObserver(zap.New(core))

			for _, msg := range tt.msgs {
				o.onDownstreamMessage(msg)
			}

			assert.Equal(t, tt.want, takeLines(logs))
		})
	}
}

func TestAuditObserver_ServerMessages(t *testing.T) {
	tests := []struct {
		name string
		msgs []pgproto3.BackendMessage
		want []auditLine
	}{
		{
			name: "command complete with a row count",
			msgs: []pgproto3.BackendMessage{&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")}},
			want: []auditLine{{"pg result", map[string]any{"command": "SELECT", "row_count": int64(2)}}},
		},
		{
			name: "command complete without a row count",
			msgs: []pgproto3.BackendMessage{&pgproto3.CommandComplete{CommandTag: []byte("SHOW")}},
			want: []auditLine{{"pg result", map[string]any{"command": "SHOW"}}},
		},
		{
			name: "empty query",
			msgs: []pgproto3.BackendMessage{&pgproto3.EmptyQueryResponse{}},
			want: []auditLine{{"pg result", map[string]any{}}},
		},
		{
			name: "function call response",
			msgs: []pgproto3.BackendMessage{&pgproto3.FunctionCallResponse{Result: []byte("1")}},
			want: []auditLine{{"pg result", map[string]any{}}},
		},
		{
			name: "error",
			msgs: []pgproto3.BackendMessage{&pgproto3.ErrorResponse{Code: "42501", Message: "permission denied for table users"}},
			want: []auditLine{{"pg result", map[string]any{
				"error_code": "42501", "error_message": "permission denied for table users",
			}}},
		},
		{
			name: "portal suspended",
			msgs: []pgproto3.BackendMessage{&pgproto3.PortalSuspended{}},
			want: []auditLine{{"pg result", map[string]any{"suspended": true}}},
		},
		{
			name: "ready for query",
			msgs: []pgproto3.BackendMessage{&pgproto3.ReadyForQuery{TxStatus: 'I'}},
			want: []auditLine{{"pg completed", map[string]any{}}},
		},
		{
			name: "never logged",
			msgs: []pgproto3.BackendMessage{
				&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, &pgproto3.CloseComplete{},
				&pgproto3.ParameterDescription{ParameterOIDs: []uint32{23}},
				&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("id")}}}, &pgproto3.NoData{},
				&pgproto3.DataRow{Values: [][]byte{[]byte("1")}},
				&pgproto3.NoticeResponse{Message: "notice"}, &pgproto3.NotificationResponse{Channel: "jobs"},
				&pgproto3.ParameterStatus{Name: "TimeZone", Value: "UTC"},
				&pgproto3.CopyInResponse{}, &pgproto3.CopyOutResponse{}, &pgproto3.CopyData{Data: []byte("1\n")}, &pgproto3.CopyDone{},
			},
			want: []auditLine{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := zapobserver.New(zap.InfoLevel)
			o := newAuditObserver(zap.New(core))

			for _, msg := range tt.msgs {
				o.onUpstreamMessage(msg)
			}

			assert.Equal(t, tt.want, takeLines(logs))
		})
	}
}

func TestStringField(t *testing.T) {
	atCap := strings.Repeat("x", maxAuditValueBytes)

	tests := []struct {
		name          string
		value         string
		want          map[string]any
		wantTruncated bool
	}{
		{name: "at the cap", value: atCap, want: map[string]any{"sql": atCap}},
		{name: "over the cap", value: atCap + "x", want: map[string]any{"sql": atCap}, wantTruncated: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := zapcore.NewMapObjectEncoder()

			field, truncated := stringField("sql", tt.value)
			field.AddTo(encoder)

			assert.Equal(t, tt.want, encoder.Fields)
			assert.Equal(t, tt.wantTruncated, truncated)
		})
	}
}

func TestTruncatedField(t *testing.T) {
	tests := []struct {
		name      string
		truncated []bool
		want      map[string]any
	}{
		{name: "nothing cut", truncated: []bool{false, false}, want: map[string]any{}},
		{name: "several values cut", truncated: []bool{true, false, true}, want: map[string]any{"truncated": true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := zapcore.NewMapObjectEncoder()

			truncatedField(tt.truncated...).AddTo(encoder)

			assert.Equal(t, tt.want, encoder.Fields)
		})
	}
}

func TestValueField(t *testing.T) {
	tests := []struct {
		name          string
		formatCodes   []int16
		values        [][]byte
		want          map[string]any
		wantTruncated bool
	}{
		{
			name:   "text and null",
			values: [][]byte{[]byte("42"), nil},
			want:   map[string]any{"parameters": []any{"42", nil}},
		},
		{
			name:        "one format code for all values",
			formatCodes: []int16{pgtype.BinaryFormatCode},
			values:      [][]byte{{0, 1}, {0xff}},
			want:        map[string]any{"parameters": []any{"AAE=", "/w=="}},
		},
		{
			name:        "one format code per value",
			formatCodes: []int16{pgtype.TextFormatCode, pgtype.BinaryFormatCode},
			values:      [][]byte{[]byte("a"), {0xff}},
			want:        map[string]any{"parameters": []any{"a", "/w=="}},
		},
		{
			name:        "fewer format codes than values",
			formatCodes: []int16{pgtype.TextFormatCode, pgtype.BinaryFormatCode},
			values:      [][]byte{[]byte("a"), {0xff}, []byte("c")},
			want:        map[string]any{"parameters": []any{"a", "/w==", "c"}},
		},
		{
			name: "no values",
			want: map[string]any{"parameters": []any{}},
		},
		{
			name:   "at the cap",
			values: [][]byte{bytes.Repeat([]byte("a"), maxAuditValueBytes-1), nil, []byte("b")},
			want:   map[string]any{"parameters": []any{strings.Repeat("a", maxAuditValueBytes-1), nil, "b"}},
		},
		{
			name:   "null after the cap is kept",
			values: [][]byte{nil, bytes.Repeat([]byte("a"), maxAuditValueBytes), nil, nil},
			want:   map[string]any{"parameters": []any{nil, strings.Repeat("a", maxAuditValueBytes), nil, nil}},
		},
		{
			name:          "over the cap cuts the crossing value and drops the rest",
			formatCodes:   []int16{pgtype.TextFormatCode, pgtype.BinaryFormatCode, pgtype.TextFormatCode},
			values:        [][]byte{bytes.Repeat([]byte("a"), maxAuditValueBytes-4), {0xff, 0xff, 0xff, 0xff}, []byte("c")},
			want:          map[string]any{"parameters": []any{strings.Repeat("a", maxAuditValueBytes-4), "////"}},
			wantTruncated: true,
		},
		{
			name:        "binary value at the cap in base64",
			formatCodes: []int16{pgtype.BinaryFormatCode},
			values:      [][]byte{bytes.Repeat([]byte{0xff}, maxAuditValueBytes/4*3)},
			want:        map[string]any{"parameters": []any{strings.Repeat("/", maxAuditValueBytes)}},
		},
		{
			name:          "binary value over the cap in base64",
			formatCodes:   []int16{pgtype.BinaryFormatCode},
			values:        [][]byte{bytes.Repeat([]byte{0xff}, maxAuditValueBytes/4*3+1)},
			want:          map[string]any{"parameters": []any{strings.Repeat("/", maxAuditValueBytes)}},
			wantTruncated: true,
		},
		{
			name:          "binary value that cannot fit a base64 group is dropped",
			formatCodes:   []int16{pgtype.TextFormatCode, pgtype.BinaryFormatCode},
			values:        [][]byte{bytes.Repeat([]byte("a"), maxAuditValueBytes-3), {0xff}},
			want:          map[string]any{"parameters": []any{strings.Repeat("a", maxAuditValueBytes-3)}},
			wantTruncated: true,
		},
		{
			name:          "first value over the cap",
			values:        [][]byte{bytes.Repeat([]byte("a"), maxAuditValueBytes+1)},
			want:          map[string]any{"parameters": []any{strings.Repeat("a", maxAuditValueBytes)}},
			wantTruncated: true,
		},
		{
			name:          "value after the cap is dropped",
			values:        [][]byte{bytes.Repeat([]byte("a"), maxAuditValueBytes), []byte("b")},
			want:          map[string]any{"parameters": []any{strings.Repeat("a", maxAuditValueBytes)}},
			wantTruncated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := zapcore.NewMapObjectEncoder()

			field, truncated := valueField("parameters", tt.formatCodes, tt.values)
			field.AddTo(encoder)

			assert.Equal(t, tt.want, encoder.Fields)
			assert.Equal(t, tt.wantTruncated, truncated)
		})
	}
}

func TestParseCommandTag(t *testing.T) {
	tests := []struct {
		tag             string
		wantCommand     string
		wantRowCount    int64
		wantHasRowCount bool
	}{
		{tag: "UPDATE 3", wantCommand: "UPDATE", wantRowCount: 3, wantHasRowCount: true},
		{tag: "SELECT 0", wantCommand: "SELECT", wantRowCount: 0, wantHasRowCount: true},
		{tag: "INSERT 0 5", wantCommand: "INSERT", wantRowCount: 5, wantHasRowCount: true},
		{tag: "CREATE TABLE", wantCommand: "CREATE TABLE"},
		{tag: "REFRESH MATERIALIZED VIEW", wantCommand: "REFRESH MATERIALIZED VIEW"},
		{tag: "BEGIN", wantCommand: "BEGIN"},
		{tag: "", wantCommand: ""},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			command, rowCount, hasRowCount := parseCommandTag([]byte(tt.tag))

			assert.Equal(t, tt.wantCommand, command)
			assert.Equal(t, tt.wantRowCount, rowCount)
			assert.Equal(t, tt.wantHasRowCount, hasRowCount)
		})
	}
}
