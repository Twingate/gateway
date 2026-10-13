// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	fieldOutcome   = "outcome"
	fieldReason    = "reason"
	outcomeSuccess = "success"
	outcomeFailure = "failure"
)

// AuditLogger writes audit events without severity level.
type AuditLogger struct {
	logger *zap.Logger
}

func NewAuditLogger(logger *zap.Logger) AuditLogger {
	return AuditLogger{logger: logger}
}

func (l AuditLogger) Log(msg string, fields ...zap.Field) {
	l.logger.Info(msg, fields...)
}

func (l AuditLogger) With(fields ...zap.Field) AuditLogger {
	return AuditLogger{logger: l.logger.With(fields...)}
}

func WithSuccess() zap.Field {
	return zap.String(fieldOutcome, outcomeSuccess)
}

func WithFailure(reason string) zap.Field {
	return zap.Inline(failure(reason))
}

type failure string

func (f failure) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString(fieldOutcome, outcomeFailure)
	enc.AddString(fieldReason, string(f))

	return nil
}
