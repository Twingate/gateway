// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"gateway/internal/config"
)

func TestNew(t *testing.T) {
	logger, err := New(config.LogConfig{System: config.LogSystemConfig{Level: zapcore.DebugLevel}})
	require.NoError(t, err)

	tests := []struct {
		name       string
		logger     *zap.Logger
		wantName   string
		wantLevel  zapcore.Level
		wantCaller bool
		wantStack  bool
	}{
		{name: "system", logger: logger.System, wantName: "system", wantLevel: zapcore.DebugLevel, wantCaller: true, wantStack: true},
		{name: "audit", logger: logger.Audit, wantName: "audit", wantLevel: zapcore.InfoLevel},
		{name: "session", logger: logger.Session, wantName: "session", wantLevel: zapcore.InfoLevel, wantCaller: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantName, tt.logger.Name())
			assert.Equal(t, tt.wantLevel, tt.logger.Level())
			assert.Equal(t, tt.wantCaller, tt.logger.Check(zapcore.InfoLevel, "").Caller.Defined)
			assert.Equal(t, tt.wantStack, tt.logger.Check(zapcore.ErrorLevel, "").Stack != "")
		})
	}
}

func TestWriters_Open(t *testing.T) {
	tests := []struct {
		name     string
		output   config.LogOutputConfig
		wantKey  string
		wantFile *os.File
	}{
		{name: "stdout", output: config.LogOutputConfig{Stdout: &config.LogStandardOutputConfig{}}, wantKey: "stdout", wantFile: os.Stdout},
		{name: "stderr", output: config.LogOutputConfig{Stderr: &config.LogStandardErrorConfig{}}, wantKey: "stderr", wantFile: os.Stderr},
		{name: "empty config defaults to stderr", output: config.LogOutputConfig{}, wantKey: "stderr", wantFile: os.Stderr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := writers{}
			writer := w.open(tt.output)

			assert.Equal(t, zapcore.Lock(tt.wantFile), writer)
			assert.Same(t, writer, w[tt.wantKey])
		})
	}

	t.Run("shares the open writer of the same output", func(t *testing.T) {
		w := writers{}
		output := config.LogOutputConfig{Stdout: &config.LogStandardOutputConfig{}}
		writer := w.open(output)

		assert.Same(t, writer, w.open(output))
	})
}
