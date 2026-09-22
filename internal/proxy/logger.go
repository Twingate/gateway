// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"gateway/internal/util/version"
)

const DefaultLoggerName = "gateway"

func NewLogger(name string, debug bool) (*zap.Logger, error) {
	logger, err := logConfig(debug).Build()
	if err != nil {
		return nil, err
	}

	logger = logger.Named(name).With(zap.String("version", version.Version))

	return logger, nil
}

func logConfig(debug bool) zap.Config {
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

	logLevel := zap.InfoLevel
	if debug {
		logLevel = zap.DebugLevel
	}

	config := zap.Config{
		Level:            zap.NewAtomicLevelAt(logLevel),
		Development:      false,
		Encoding:         "json",
		EncoderConfig:    encoderConfig,
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	return config
}
