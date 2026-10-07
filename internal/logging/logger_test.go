// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"gateway/internal/config"
)

// captureStream replaces the process stream that zap resolves when it opens "stderr" or "stdout"
// with a pipe. The returned function restores the stream and returns everything written to it.
func captureStream(t *testing.T, stream **os.File) func() []byte {
	t.Helper()

	reader, writer, err := os.Pipe()
	require.NoError(t, err)

	original := *stream
	*stream = writer

	t.Cleanup(func() { *stream = original })

	return func() []byte {
		*stream = original

		require.NoError(t, writer.Close())

		content, err := io.ReadAll(reader)
		require.NoError(t, err)
		require.NoError(t, reader.Close())

		return content
	}
}

func parseLogLines(t *testing.T, content []byte) []map[string]any {
	t.Helper()

	var lines []map[string]any

	for line := range bytes.Lines(content) {
		payload := map[string]any{}
		require.NoError(t, json.Unmarshal(line, &payload))

		lines = append(lines, payload)
	}

	return lines
}

func TestNew_SystemLevel(t *testing.T) {
	tests := []struct {
		name            string
		cfg             config.LogConfig
		wantSystemLevel zapcore.Level
	}{
		{name: "omitted system config is info", wantSystemLevel: zapcore.InfoLevel},
		{
			name:            "configured to debug level",
			cfg:             config.LogConfig{System: config.LogSystemConfig{Level: zapcore.DebugLevel}},
			wantSystemLevel: zapcore.DebugLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := New(tt.cfg)
			require.NoError(t, err)

			assert.Equal(t, tt.wantSystemLevel, logger.System.Level())
		})
	}
}

func TestNew_WritesEachCategoryToOutput(t *testing.T) {
	readStderr := captureStream(t, &os.Stderr)
	readStdout := captureStream(t, &os.Stdout)

	logger, err := New(config.LogConfig{
		System: config.LogSystemConfig{Output: config.LogOutputConfig{Stderr: &config.LogStandardErrorConfig{}}},
		Audit:  config.LogAuditConfig{Output: config.LogOutputConfig{Stdout: &config.LogStandardOutputConfig{}}},
	})
	require.NoError(t, err)

	logger.System.Info("system line")
	logger.Audit.Info("audit line")
	logger.Session.Info("session line")

	stderrLines := parseLogLines(t, readStderr())
	stdoutLines := parseLogLines(t, readStdout())
	require.Len(t, stderrLines, 2)
	require.Len(t, stdoutLines, 1)

	tests := []struct {
		name       string
		line       map[string]any
		wantLogger string
		wantMsg    string
		wantCaller bool
	}{
		{name: "system on stderr", line: stderrLines[0], wantLogger: "system", wantMsg: "system line", wantCaller: true},
		{name: "audit on stdout without caller", line: stdoutLines[0], wantLogger: "audit", wantMsg: "audit line"},
		{name: "session on stderr when its output is omitted", line: stderrLines[1], wantLogger: "session", wantMsg: "session line", wantCaller: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.line["ts"])
			delete(tt.line, "ts")

			if tt.wantCaller {
				assert.Contains(t, tt.line["caller"], "logging/logger_test.go:")
				delete(tt.line, "caller")
			}

			assert.Equal(t, map[string]any{
				"logger":    tt.wantLogger,
				"version":   "dev",
				"levelname": "info",
				"message":   tt.wantMsg,
			}, tt.line)
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
