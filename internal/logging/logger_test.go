// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
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

func readLogLines(t *testing.T, path string) []map[string]any {
	t.Helper()

	content, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err)

	return parseLogLines(t, content)
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
	sessionPath := filepath.Join(t.TempDir(), "sessions.log")

	logger, err := New(config.LogConfig{
		System:           config.LogSystemConfig{Output: config.LogOutputConfig{Stderr: &config.LogStandardErrorConfig{}}},
		Audit:            config.LogAuditConfig{Output: config.LogOutputConfig{Stdout: &config.LogStandardOutputConfig{}}},
		SessionRecording: config.SessionRecordingConfig{Output: config.LogOutputConfig{File: &config.LogFileOutputConfig{Path: sessionPath}}},
	})
	require.NoError(t, err)

	t.Cleanup(func() { _ = logger.Close() })

	logger.System.Info("system line")
	logger.Audit.Info("audit line")
	logger.Session.Info("session line")

	stderrLines := parseLogLines(t, readStderr())
	stdoutLines := parseLogLines(t, readStdout())
	sessionLines := readLogLines(t, sessionPath)
	require.Len(t, stderrLines, 1)
	require.Len(t, stdoutLines, 1)
	require.Len(t, sessionLines, 1)

	tests := []struct {
		name       string
		line       map[string]any
		wantLogger string
		wantMsg    string
		wantCaller bool
	}{
		{name: "system on stderr", line: stderrLines[0], wantLogger: "system", wantMsg: "system line", wantCaller: true},
		{name: "audit on stdout without caller", line: stdoutLines[0], wantLogger: "audit", wantMsg: "audit line"},
		{name: "session in its file", line: sessionLines[0], wantLogger: "session", wantMsg: "session line", wantCaller: true},
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
			writer, err := w.open(tt.output)
			require.NoError(t, err)

			assert.Equal(t, zapcore.Lock(tt.wantFile), writer)
			assert.Same(t, writer, w[tt.wantKey])
		})
	}

	t.Run("shares the open writer of the same output", func(t *testing.T) {
		w := writers{}
		output := config.LogOutputConfig{Stdout: &config.LogStandardOutputConfig{}}
		writer, err := w.open(output)
		require.NoError(t, err)

		shared, err := w.open(output)
		require.NoError(t, err)

		assert.Same(t, writer, shared)
	})

	t.Run("a file named stdout does not share the stdout stream", func(t *testing.T) {
		t.Chdir(t.TempDir())

		w := writers{}
		stdout, err := w.open(config.LogOutputConfig{Stdout: &config.LogStandardOutputConfig{}})
		require.NoError(t, err)

		file, err := w.open(config.LogOutputConfig{File: &config.LogFileOutputConfig{Path: "stdout"}})
		require.NoError(t, err)

		assert.NotSame(t, stdout, file)
		assert.FileExists(t, "stdout")
	})
}

func TestNew_UnwritableFile(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(parent, nil, 0600))

	_, err := New(config.LogConfig{
		Audit: config.LogAuditConfig{Output: config.LogOutputConfig{File: &config.LogFileOutputConfig{Path: filepath.Join(parent, "audit.log")}}},
	})

	assert.ErrorContains(t, err, "audit: ")
}

type mockWriter struct {
	zapcore.WriteSyncer

	closed bool
}

func (m *mockWriter) Close() error {
	m.closed = true

	return nil
}

func TestLogger_Close(t *testing.T) {
	writer := &mockWriter{}
	logger := Logger{writers: writers{"/var/log/gateway/audit.log": writer, "stdout": zapcore.Lock(os.Stdout)}}

	require.NoError(t, logger.Close())
	assert.True(t, writer.closed)
}
