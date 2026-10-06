// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"gateway/internal/config"
	"gateway/internal/util/version"
)

const (
	SystemLoggerName  = "system"
	AuditLoggerName   = "audit"
	SessionLoggerName = "session"
)

type Logger struct {
	System  *zap.Logger
	Audit   *zap.Logger
	Session *zap.Logger
}

// New builds the loggers from the log configuration.
func New(cfg config.LogConfig) (Logger, error) {
	system, err := newLogger(SystemLoggerName, cfg.System.Output, cfg.System.Level, false)
	if err != nil {
		return Logger{}, err
	}

	audit, err := newLogger(AuditLoggerName, cfg.Audit.Output, zapcore.InfoLevel, true)
	if err != nil {
		return Logger{}, err
	}

	session, err := newLogger(SessionLoggerName, cfg.SessionRecording.Output, zapcore.InfoLevel, false)
	if err != nil {
		return Logger{}, err
	}

	return Logger{System: system, Audit: audit, Session: session}, nil
}

func newLogger(name string, output config.LogOutputConfig, level zapcore.Level, disableCaller bool) (*zap.Logger, error) {
	logger, err := logConfig(level, outputPath(output), disableCaller).Build()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	return logger.Named(name).With(zap.String("version", version.Version)), nil
}

func outputPath(output config.LogOutputConfig) string {
	switch {
	case output.Stdout != nil:
		return "stdout"
	case output.Stderr != nil:
		fallthrough
	default:
		return "stderr"
	}
}

func logConfig(level zapcore.Level, outputPath string, disableCaller bool) zap.Config {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "levelname",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "message",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	return zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Development:      false,
		DisableCaller:    disableCaller,
		Encoding:         "json",
		EncoderConfig:    encoderConfig,
		OutputPaths:      []string{outputPath},
		ErrorOutputPaths: []string{"stderr"},
	}
}
