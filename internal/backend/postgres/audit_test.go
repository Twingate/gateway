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
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	zapobserver "go.uber.org/zap/zaptest/observer"
)

type auditLine struct {
	message string
	fields  map[string]any
}

type testAuditObserver struct {
	*auditObserver

	logs *zapobserver.ObservedLogs
}

func newTestAuditObserver() *testAuditObserver {
	core, logs := zapobserver.New(zap.InfoLevel)

	return &testAuditObserver{auditObserver: newAuditObserver(zap.New(core)), logs: logs}
}

func (o *testAuditObserver) fromClient(msgs ...pgproto3.FrontendMessage) {
	for _, msg := range msgs {
		o.onDownstreamMessage(msg)
	}
}

func (o *testAuditObserver) fromServer(msgs ...pgproto3.BackendMessage) {
	for _, msg := range msgs {
		o.onUpstreamMessage(msg)
	}
}

// takeLines returns the auditLine written since the last call. duration_ms is checked here and
// dropped. A test calls it and ignores the result to drop the lines its setup wrote, so the next
// call returns only the lines of the messages under test.
func (o *testAuditObserver) takeLines(t *testing.T) []auditLine {
	t.Helper()

	lines := []auditLine{}

	for _, entry := range o.logs.TakeAll() {
		fields := entry.ContextMap()

		_, hasRequest := fields[fieldRequestID]
		_, hasDuration := fields[fieldDurationMS]

		if entry.Message == "pg result" || entry.Message == "pg completed" {
			assert.Equal(t, hasRequest, hasDuration, "%s: duration_ms must come with request_id", entry.Message)
		}

		delete(fields, fieldDurationMS)

		lines = append(lines, auditLine{message: entry.Message, fields: fields})
	}

	return lines
}

func TestAuditObserver_ClientMessages(t *testing.T) {
	tests := []struct {
		name string
		msgs []pgproto3.FrontendMessage
		want []auditLine
	}{
		{
			name: "query",
			msgs: []pgproto3.FrontendMessage{&pgproto3.Query{String: "SELECT 1"}},
			want: []auditLine{{"pg query", map[string]any{"request_id": uint64(1), "sql": "SELECT 1"}}},
		},
		{
			name: "parse",
			msgs: []pgproto3.FrontendMessage{&pgproto3.Parse{Name: "stmtcache_3", Query: "SELECT $1"}},
			want: []auditLine{{"pg parse", map[string]any{"request_id": uint64(1), "statement_name": "stmtcache_3", "sql": "SELECT $1"}}},
		},
		{
			name: "bind",
			msgs: []pgproto3.FrontendMessage{&pgproto3.Bind{PreparedStatement: "stmtcache_3", Parameters: [][]byte{[]byte("42")}}},
			want: []auditLine{{"pg bind", map[string]any{
				"request_id": uint64(1), "statement_name": "stmtcache_3", "portal_name": "", "parameters": []any{"42"},
			}}},
		},
		{
			name: "execute",
			msgs: []pgproto3.FrontendMessage{&pgproto3.Execute{Portal: "p1", MaxRows: 10}},
			want: []auditLine{{"pg execute", map[string]any{"request_id": uint64(1), "portal_name": "p1", "max_rows": uint32(10)}}},
		},
		{
			name: "function call",
			msgs: []pgproto3.FrontendMessage{
				&pgproto3.FunctionCall{Function: 1234, ArgFormatCodes: []uint16{pgtype.BinaryFormatCode}, Arguments: [][]byte{{1}}},
			},
			want: []auditLine{{"pg function_call", map[string]any{
				"request_id": uint64(1), "function": uint32(1234), "arguments": []any{"AQ=="},
			}}},
		},
		{
			name: "never logged",
			msgs: []pgproto3.FrontendMessage{
				&pgproto3.Describe{ObjectType: objectTypeStatement, Name: "s1"},
				&pgproto3.Close{ObjectType: objectTypeStatement, Name: "s1"}, &pgproto3.Close{ObjectType: objectTypePortal, Name: "p1"},
				&pgproto3.Sync{}, &pgproto3.Flush{},
				&pgproto3.CopyData{Data: []byte("1\tone\n")}, &pgproto3.CopyDone{}, &pgproto3.CopyFail{Message: "aborted"},
				&pgproto3.Terminate{},
			},
			want: []auditLine{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := newTestAuditObserver()
			o.fromClient(tt.msgs...)

			assert.Equal(t, tt.want, o.takeLines(t))
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
			name: "command complete with a row count and columns",
			msgs: []pgproto3.BackendMessage{
				&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("id")}, {Name: []byte("email")}}},
				&pgproto3.DataRow{Values: [][]byte{[]byte("1"), []byte("a@acme.int")}},
				&pgproto3.DataRow{Values: [][]byte{[]byte("2"), []byte("b@acme.int")}},
				&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
			},
			want: []auditLine{{"pg result", map[string]any{
				"request_id": uint64(1), "command": "SELECT", "row_count": int64(2), "columns": []any{"id", "email"},
			}}},
		},
		{
			name: "command complete without a row count",
			msgs: []pgproto3.BackendMessage{
				&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("TimeZone")}}},
				&pgproto3.DataRow{Values: [][]byte{[]byte("UTC")}},
				&pgproto3.CommandComplete{CommandTag: []byte("SHOW")},
			},
			want: []auditLine{{"pg result", map[string]any{"request_id": uint64(1), "command": "SHOW", "columns": []any{"TimeZone"}}}},
		},
		{
			name: "empty query",
			msgs: []pgproto3.BackendMessage{&pgproto3.EmptyQueryResponse{}},
			want: []auditLine{{"pg result", map[string]any{"request_id": uint64(1)}}},
		},
		{
			name: "error",
			msgs: []pgproto3.BackendMessage{&pgproto3.ErrorResponse{Code: "42501", Message: "permission denied for table users"}},
			want: []auditLine{{"pg result", map[string]any{
				"request_id": uint64(1), "error_code": "42501", "error_message": "permission denied for table users",
			}}},
		},
		{
			name: "never logged",
			msgs: []pgproto3.BackendMessage{
				&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}, &pgproto3.NoData{}, &pgproto3.CloseComplete{},
				&pgproto3.ParameterDescription{ParameterOIDs: []uint32{23}}, &pgproto3.FunctionCallResponse{},
				&pgproto3.NoticeResponse{Message: "notice"}, &pgproto3.NotificationResponse{Channel: "jobs"},
				&pgproto3.ParameterStatus{Name: "TimeZone", Value: "UTC"},
				&pgproto3.CopyInResponse{}, &pgproto3.CopyOutResponse{}, &pgproto3.CopyData{Data: []byte("1\n")}, &pgproto3.CopyDone{},
			},
			want: []auditLine{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := newTestAuditObserver()
			o.fromClient(&pgproto3.Query{String: "SELECT 1"})
			o.takeLines(t)

			o.fromServer(tt.msgs...)

			assert.Equal(t, tt.want, o.takeLines(t))
		})
	}
}

func TestAuditObserver_ReadyForQuery(t *testing.T) {
	tests := []struct {
		name        string
		txStatus    byte
		wantPortals map[string]string
	}{
		{name: "transaction open", txStatus: 'T', wantPortals: map[string]string{"p1": "s1"}},
		{name: "transaction ended", txStatus: 'I', wantPortals: map[string]string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := newTestAuditObserver()
			o.fromClient(
				&pgproto3.Bind{DestinationPortal: "p1", PreparedStatement: "s1"},
				&pgproto3.Describe{ObjectType: objectTypePortal, Name: "p1"},
				&pgproto3.Describe{ObjectType: objectTypeStatement, Name: "s1"},
				&pgproto3.Execute{Portal: "p1"},
			)
			o.fromServer(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("id")}}})
			// Ignore client message logs
			o.takeLines(t)

			o.fromServer(&pgproto3.ReadyForQuery{TxStatus: tt.txStatus})

			assert.Equal(t, []auditLine{{"pg completed", map[string]any{"request_id": uint64(1)}}}, o.takeLines(t))
			assert.True(t, o.startedAt.IsZero())
			assert.Nil(t, o.columns)
			assert.Empty(t, o.describes)
			assert.Empty(t, o.executes)
			assert.Equal(t, tt.wantPortals, o.portals)
		})
	}
}

func TestAuditObserver_RequestNumbering(t *testing.T) {
	o := newTestAuditObserver()

	for want := uint64(1); want <= 3; want++ {
		o.fromClient(&pgproto3.Query{String: "SELECT 1"})
		o.fromServer(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}, &pgproto3.ReadyForQuery{TxStatus: 'I'})

		lines := o.takeLines(t)
		require.Len(t, lines, 3)

		for _, line := range lines {
			assert.Equal(t, want, line.fields["request_id"], line.message)
		}
	}
}

func TestAuditObserver_SimpleQuery(t *testing.T) {
	o := newTestAuditObserver()

	o.fromClient(&pgproto3.Query{String: "SELECT id, email FROM users WHERE org_id = 42"})
	o.fromServer(
		&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("id")}, {Name: []byte("email")}}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("1"), []byte("a@acme.int")}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("2"), []byte("b@acme.int")}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)

	assert.Equal(t, []auditLine{
		{"pg query", map[string]any{"request_id": uint64(1), "sql": "SELECT id, email FROM users WHERE org_id = 42"}},
		{"pg result", map[string]any{"request_id": uint64(1), "command": "SELECT", "row_count": int64(2), "columns": []any{"id", "email"}}},
		{"pg completed", map[string]any{"request_id": uint64(1)}},
	}, o.takeLines(t))
}

func TestAuditObserver_ExtendedQuery(t *testing.T) {
	o := newTestAuditObserver()

	// Query a maximum of 2 rows and continue to fetch with the next `execute`
	o.fromClient(
		&pgproto3.Parse{Query: "SELECT id, email FROM users WHERE org_id = $1"},
		&pgproto3.Bind{DestinationPortal: "C_1", Parameters: [][]byte{[]byte("42")}},
		&pgproto3.Describe{ObjectType: objectTypePortal, Name: "C_1"},
		&pgproto3.Execute{Portal: "C_1", MaxRows: 2},
		&pgproto3.Sync{},
	)
	o.fromServer(
		&pgproto3.ParseComplete{},
		&pgproto3.BindComplete{},
		&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("id")}, {Name: []byte("email")}}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("1"), []byte("a@acme.int")}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("2"), []byte("b@acme.int")}},
		&pgproto3.PortalSuspended{},
		&pgproto3.ReadyForQuery{TxStatus: 'T'},
	)

	assert.Equal(t, []auditLine{
		{"pg parse", map[string]any{"request_id": uint64(1), "statement_name": "", "sql": "SELECT id, email FROM users WHERE org_id = $1"}},
		{"pg bind", map[string]any{"request_id": uint64(1), "statement_name": "", "portal_name": "C_1", "parameters": []any{"42"}}},
		{"pg execute", map[string]any{"request_id": uint64(1), "portal_name": "C_1", "max_rows": uint32(2)}},
		{"pg completed", map[string]any{"request_id": uint64(1)}},
	}, o.takeLines(t))

	o.fromClient(&pgproto3.Execute{Portal: "C_1", MaxRows: 0}, &pgproto3.Sync{})
	o.fromServer(
		&pgproto3.DataRow{Values: [][]byte{[]byte("3"), []byte("c@acme.int")}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'T'},
	)

	assert.Equal(t, []auditLine{
		{"pg execute", map[string]any{"request_id": uint64(2), "portal_name": "C_1", "max_rows": uint32(0)}},
		{"pg result", map[string]any{"request_id": uint64(2), "command": "SELECT", "row_count": int64(1)}},
		{"pg completed", map[string]any{"request_id": uint64(2)}},
	}, o.takeLines(t))
}

// TestAuditObserver_PreparedStatement runs a statement the way a driver with a statement cache does.
func TestAuditObserver_PreparedStatement(t *testing.T) {
	o := newTestAuditObserver()

	o.fromClient(
		&pgproto3.Parse{Name: "stmtcache_3", Query: "SELECT id, email FROM users WHERE org_id = $1"},
		&pgproto3.Describe{ObjectType: objectTypeStatement, Name: "stmtcache_3"},
		&pgproto3.Sync{},
	)
	o.fromServer(
		&pgproto3.ParseComplete{},
		&pgproto3.ParameterDescription{ParameterOIDs: []uint32{23}},
		&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("id")}, {Name: []byte("email")}}},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)

	assert.Equal(t, []auditLine{
		{"pg parse", map[string]any{"request_id": uint64(1), "statement_name": "stmtcache_3", "sql": "SELECT id, email FROM users WHERE org_id = $1"}},
		{"pg completed", map[string]any{"request_id": uint64(1)}},
	}, o.takeLines(t))

	// Query using the cached statement
	o.fromClient(
		&pgproto3.Bind{PreparedStatement: "stmtcache_3", Parameters: [][]byte{[]byte("42")}},
		&pgproto3.Execute{},
		&pgproto3.Sync{},
	)
	o.fromServer(
		&pgproto3.BindComplete{},
		&pgproto3.DataRow{Values: [][]byte{[]byte("1"), []byte("a@acme.int")}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("2"), []byte("b@acme.int")}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)

	assert.Equal(t, []auditLine{
		{"pg bind", map[string]any{"request_id": uint64(2), "statement_name": "stmtcache_3", "portal_name": "", "parameters": []any{"42"}}},
		{"pg execute", map[string]any{"request_id": uint64(2), "portal_name": "", "max_rows": uint32(0)}},
		{"pg result", map[string]any{"request_id": uint64(2), "command": "SELECT", "row_count": int64(2), "columns": []any{"id", "email"}}},
		{"pg completed", map[string]any{"request_id": uint64(2)}},
	}, o.takeLines(t))
}

// prepare runs a driver's prepare round trip, which describes the statement before any execute.
func (o *testAuditObserver) prepare(t *testing.T, name string, columns ...string) {
	t.Helper()

	o.fromClient(&pgproto3.Parse{Name: name, Query: "SELECT"}, &pgproto3.Describe{ObjectType: objectTypeStatement, Name: name}, &pgproto3.Sync{})
	o.fromServer(&pgproto3.ParseComplete{}, &pgproto3.ParameterDescription{})

	if columns == nil {
		o.fromServer(&pgproto3.NoData{})
	} else {
		fields := make([]pgproto3.FieldDescription, len(columns))
		for i, column := range columns {
			fields[i] = pgproto3.FieldDescription{Name: []byte(column)}
		}

		o.fromServer(&pgproto3.RowDescription{Fields: fields})
	}

	o.fromServer(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	// Ignore audit lines up to this point
	o.takeLines(t)
}

// TestAuditObserver_MultiplePreparedStatements runs two prepared statements in one request: the
// second statement gets its own columns only when the first result consumed its Execute.
func TestAuditObserver_MultiplePreparedStatements(t *testing.T) {
	selectResult := &pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}

	tests := []struct {
		name      string
		s1Columns []string
		s1MaxRows uint32
		s1Result  pgproto3.BackendMessage
		want      []auditLine
	}{
		{
			name: "both complete", s1Columns: []string{"id"}, s1Result: selectResult,
			want: []auditLine{
				{"pg bind", map[string]any{"request_id": uint64(3), "statement_name": "s1", "portal_name": "", "parameters": []any{}}},
				{"pg execute", map[string]any{"request_id": uint64(3), "portal_name": "", "max_rows": uint32(0)}},
				{"pg bind", map[string]any{"request_id": uint64(3), "statement_name": "s2", "portal_name": "", "parameters": []any{}}},
				{"pg execute", map[string]any{"request_id": uint64(3), "portal_name": "", "max_rows": uint32(0)}},
				{"pg result", map[string]any{"request_id": uint64(3), "command": "SELECT", "row_count": int64(1), "columns": []any{"id"}}},
				{"pg result", map[string]any{"request_id": uint64(3), "command": "SELECT", "row_count": int64(1), "columns": []any{"email"}}},
				{"pg completed", map[string]any{"request_id": uint64(3)}},
			},
		},
		{
			name: "first portal suspended", s1Columns: []string{"id"}, s1MaxRows: 1, s1Result: &pgproto3.PortalSuspended{},
			want: []auditLine{
				{"pg bind", map[string]any{"request_id": uint64(3), "statement_name": "s1", "portal_name": "", "parameters": []any{}}},
				{"pg execute", map[string]any{"request_id": uint64(3), "portal_name": "", "max_rows": uint32(1)}},
				{"pg bind", map[string]any{"request_id": uint64(3), "statement_name": "s2", "portal_name": "", "parameters": []any{}}},
				{"pg execute", map[string]any{"request_id": uint64(3), "portal_name": "", "max_rows": uint32(0)}},
				{"pg result", map[string]any{"request_id": uint64(3), "command": "SELECT", "row_count": int64(1), "columns": []any{"email"}}},
				{"pg completed", map[string]any{"request_id": uint64(3)}},
			},
		},
		{
			name: "first empty query", s1Result: &pgproto3.EmptyQueryResponse{},
			want: []auditLine{
				{"pg bind", map[string]any{"request_id": uint64(3), "statement_name": "s1", "portal_name": "", "parameters": []any{}}},
				{"pg execute", map[string]any{"request_id": uint64(3), "portal_name": "", "max_rows": uint32(0)}},
				{"pg bind", map[string]any{"request_id": uint64(3), "statement_name": "s2", "portal_name": "", "parameters": []any{}}},
				{"pg execute", map[string]any{"request_id": uint64(3), "portal_name": "", "max_rows": uint32(0)}},
				{"pg result", map[string]any{"request_id": uint64(3)}},
				{"pg result", map[string]any{"request_id": uint64(3), "command": "SELECT", "row_count": int64(1), "columns": []any{"email"}}},
				{"pg completed", map[string]any{"request_id": uint64(3)}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := newTestAuditObserver()
			o.prepare(t, "s1", tt.s1Columns...)
			o.prepare(t, "s2", "email")

			o.fromClient(
				&pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Execute{MaxRows: tt.s1MaxRows},
				&pgproto3.Bind{PreparedStatement: "s2"}, &pgproto3.Execute{},
				&pgproto3.Sync{},
			)
			o.fromServer(&pgproto3.BindComplete{}, tt.s1Result, &pgproto3.BindComplete{}, selectResult, &pgproto3.ReadyForQuery{TxStatus: 'I'})

			assert.Equal(t, tt.want, o.takeLines(t))
		})
	}
}

// TestAuditObserver_NoOpenRequest checks a server message that arrives between a ReadyForQuery
// and the client's next message. It belongs to no request and the next client message still
// takes the next number.
func TestAuditObserver_NoOpenRequest(t *testing.T) {
	o := newTestAuditObserver()

	o.fromServer(
		&pgproto3.ErrorResponse{Code: "57P01", Message: "terminating connection due to administrator command"},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)

	assert.Equal(t, []auditLine{
		{"pg result", map[string]any{"error_code": "57P01", "error_message": "terminating connection due to administrator command"}},
	}, o.takeLines(t))

	o.fromClient(&pgproto3.Query{String: "SELECT 1"})

	assert.Equal(t, []auditLine{{"pg query", map[string]any{"request_id": uint64(1), "sql": "SELECT 1"}}}, o.takeLines(t))
}

func TestStringFields(t *testing.T) {
	atCap := strings.Repeat("x", maxAuditValueBytes)

	tests := []struct {
		name  string
		value string
		want  map[string]any
	}{
		{name: "at the cap", value: atCap, want: map[string]any{"sql": atCap}},
		{name: "over the cap", value: atCap + "x", want: map[string]any{"sql": atCap, "truncated": true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := zapcore.NewMapObjectEncoder()

			for _, field := range stringFields("sql", tt.value) {
				field.AddTo(encoder)
			}

			assert.Equal(t, tt.want, encoder.Fields)
		})
	}
}

func TestValueFields(t *testing.T) {
	tests := []struct {
		name        string
		formatCodes []int16
		values      [][]byte
		want        map[string]any
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
			name:        "over the cap cuts the crossing value and drops the rest",
			formatCodes: []int16{pgtype.TextFormatCode, pgtype.BinaryFormatCode, pgtype.TextFormatCode},
			values:      [][]byte{bytes.Repeat([]byte("a"), maxAuditValueBytes-1), {0xff, 0xff}, []byte("c")},
			want:        map[string]any{"parameters": []any{strings.Repeat("a", maxAuditValueBytes-1), "/w=="}, "truncated": true},
		},
		{
			name:   "first value over the cap",
			values: [][]byte{bytes.Repeat([]byte("a"), maxAuditValueBytes+1)},
			want:   map[string]any{"parameters": []any{strings.Repeat("a", maxAuditValueBytes)}, "truncated": true},
		},
		{
			name:   "value after the cap is dropped",
			values: [][]byte{bytes.Repeat([]byte("a"), maxAuditValueBytes), []byte("b")},
			want:   map[string]any{"parameters": []any{strings.Repeat("a", maxAuditValueBytes)}, "truncated": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := zapcore.NewMapObjectEncoder()

			for _, field := range valueFields("parameters", tt.formatCodes, tt.values) {
				field.AddTo(encoder)
			}

			assert.Equal(t, tt.want, encoder.Fields)
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
