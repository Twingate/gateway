// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/DeRuina/timberjack"
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

	writers writers
}

// New builds the loggers from the log configuration. Categories configured with the same output
// share one writer.
func New(cfg config.LogConfig) (Logger, error) {
	w := writers{}

	var err error

	system, err := w.newLogger(SystemLoggerName, cfg.System.Output, cfg.System.Level, false)
	if err != nil {
		return Logger{}, err
	}

	audit, err := w.newLogger(AuditLoggerName, cfg.Audit.Output, zapcore.InfoLevel, true)
	if err != nil {
		return Logger{}, err
	}

	session, err := w.newLogger(SessionLoggerName, cfg.SessionRecording.Output, zapcore.InfoLevel, false)
	if err != nil {
		return Logger{}, err
	}

	return Logger{
		System:  system,
		Audit:   audit,
		Session: session,
		writers: w,
	}, nil
}

// Close stops the timberjack writers so an ongoing backup compression for a file can finish.
// Stdout and stderr are not closers and stay open.
func (l Logger) Close() error {
	var errs []error

	for _, writer := range l.writers {
		if closer, ok := writer.(io.Closer); ok {
			errs = append(errs, closer.Close())
		}
	}

	return errors.Join(errs...)
}

// writers holds every writer opened so far, keyed by output name or file path.
// Loggers configured with the same output share one writer.
type writers map[string]zapcore.WriteSyncer

func (w writers) newLogger(name string, output config.LogOutputConfig, level zapcore.Level, disableCaller bool) (*zap.Logger, error) {
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

	writer, err := w.open(output)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	core := zapcore.NewCore(zapcore.NewJSONEncoder(encoderConfig), writer, level)
	logger := zap.New(core, zap.WithCaller(!disableCaller), zap.AddStacktrace(zapcore.ErrorLevel))

	return logger.Named(name).With(zap.String("version", version.Version)), nil
}

func (w writers) open(output config.LogOutputConfig) (zapcore.WriteSyncer, error) {
	var key string

	switch {
	case output.Stdout != nil:
		key = "stdout"
	case output.File != nil:
		key = "file:" + output.File.Path
	case output.Stderr != nil:
		fallthrough
	default:
		key = "stderr"
	}

	if writer, opened := w[key]; opened {
		return writer, nil
	}

	writer, err := newWriter(output)
	if err != nil {
		return nil, err
	}

	w[key] = writer

	return writer, nil
}

func newWriter(output config.LogOutputConfig) (zapcore.WriteSyncer, error) {
	switch {
	case output.Stdout != nil:
		return zapcore.Lock(os.Stdout), nil
	case output.File != nil:
		writer := &timberjack.Logger{
			Filename:    output.File.Path,
			MaxSize:     output.File.Rotation.GetMaxSize(),
			MaxBackups:  output.File.Rotation.GetMaxBackupFiles(),
			MaxAge:      output.File.Rotation.GetMaxBackupAge(),
			Compression: output.File.Rotation.GetCompression(),
		}

		// timberjack opens the file on the first write, so an empty write opens it now and an
		// unwritable path fails startup instead of every log line.
		if _, err := writer.Write(nil); err != nil {
			return nil, err
		}

		return writer, nil
	case output.Stderr != nil:
		fallthrough
	default:
		return zapcore.Lock(os.Stderr), nil
	}
}
