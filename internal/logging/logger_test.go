// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"os"
	"path/filepath"
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
		t.Cleanup(func() { _ = Logger{writers: w}.Close() })

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
