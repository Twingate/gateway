// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"os"

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

// New builds the loggers from the log configuration. Categories configured with the same output
// share one writer.
func New(cfg config.LogConfig) (Logger, error) {
	w := writers{}

	return Logger{
		System:  w.newLogger(SystemLoggerName, cfg.System.Output, cfg.System.Level, false, true),
		Audit:   w.newLogger(AuditLoggerName, cfg.Audit.Output, zapcore.InfoLevel, true, false),
		Session: w.newLogger(SessionLoggerName, cfg.SessionRecording.Output, zapcore.InfoLevel, false, false),
	}, nil
}

// writers holds every writer opened so far, keyed by output name.
// Loggers configured with the same output share one writer.
type writers map[string]zapcore.WriteSyncer

func (w writers) newLogger(name string, output config.LogOutputConfig, level zapcore.Level, disableCaller bool, addStacktrace bool) *zap.Logger {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "levelname",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	opts := []zap.Option{zap.WithCaller(!disableCaller)}
	if addStacktrace {
		opts = append(opts, zap.AddStacktrace(zapcore.ErrorLevel))
	}

	core := zapcore.NewCore(zapcore.NewJSONEncoder(encoderConfig), w.open(output), level)
	logger := zap.New(core, opts...)

	return logger.Named(name).With(zap.String("version", version.Version))
}

func (w writers) open(output config.LogOutputConfig) zapcore.WriteSyncer {
	var key string

	switch {
	case output.Stdout != nil:
		key = "stdout"
	case output.Stderr != nil:
		fallthrough
	default:
		key = "stderr"
	}

	if writer, opened := w[key]; opened {
		return writer
	}

	w[key] = newWriter(output)

	return w[key]
}

func newWriter(output config.LogOutputConfig) zapcore.WriteSyncer {
	switch {
	case output.Stdout != nil:
		return zapcore.Lock(os.Stdout)
	case output.Stderr != nil:
		fallthrough
	default:
		return zapcore.Lock(os.Stderr)
	}
}
