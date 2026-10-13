// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestAuditLogger_Log(t *testing.T) {
	tests := []struct {
		name   string
		fields []zap.Field
		want   map[string]any
	}{
		{name: "no outcome", want: map[string]any{"conn_id": "c1"}},
		{name: "success", fields: []zap.Field{WithSuccess()}, want: map[string]any{"conn_id": "c1", "outcome": "success"}},
		{name: "failure", fields: []zap.Field{WithFailure("token_expired")}, want: map[string]any{"conn_id": "c1", "outcome": "failure", "reason": "token_expired"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			logger := NewAuditLogger(zap.New(core)).With(zap.String("conn_id", "c1"))

			logger.Log("event", tt.fields...)

			require.Len(t, logs.All(), 1)
			entry := logs.All()[0]
			assert.Equal(t, zapcore.InfoLevel, entry.Level)
			assert.Equal(t, "event", entry.Message)
			assert.Equal(t, tt.want, entry.ContextMap())
		})
	}
}
