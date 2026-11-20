// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sessionrecorder

import (
	"bytes"
	"io"
	"strconv"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	gatewayconfig "gateway/internal/config"
	yamlutil "gateway/internal/util/yaml"
)

// newBenchLogger returns a JSON logger that discards its output, so benchmarks include the cost
// of encoding the flushed asciicast.
func newBenchLogger() *zap.Logger {
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())

	return zap.New(zapcore.NewCore(encoder, zapcore.AddSync(io.Discard), zapcore.InfoLevel))
}

// terminalOutput is a typical chunk of terminal output, including escape sequences that need JSON escaping.
var terminalOutput = bytes.Repeat([]byte("\x1b[32mtotal 42\x1b[0m drwxr-xr-x 2 root 4096 file.txt\r\n"), 2)

func BenchmarkRecorder_WriteOutputEvent(b *testing.B) {
	RegisterRecordedSessionMetrics("bench", prometheus.NewRegistry())

	sizes := []struct {
		name    string
		maxSize yamlutil.ByteSize
	}{
		{name: "segment=64KiB", maxSize: 64 * 1024},
		{name: "segment=256KiB", maxSize: 256 * 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			r := New(newBenchLogger(), gatewayconfig.SessionRecordingSegmentConfig{MaxSize: size.maxSize})
			if err := r.WriteHeader(AsciicastHeader{Version: 2, Width: 80, Height: 24}); err != nil {
				b.Fatal(err)
			}

			b.SetBytes(int64(len(terminalOutput)))
			b.ReportAllocs()

			for b.Loop() {
				if err := r.WriteOutputEvent(terminalOutput); err != nil {
					b.Fatal(err)
				}
			}

			b.StopTimer()
			r.Stop()
		})
	}
}

// BenchmarkRecorder_FillSegment measures buffering a full segment of events and flushing it.
func BenchmarkRecorder_FillSegment(b *testing.B) {
	RegisterRecordedSessionMetrics("bench", prometheus.NewRegistry())

	for _, events := range []int{1_000, 4_000} {
		b.Run("events="+strconv.Itoa(events), func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				r := New(newBenchLogger(), gatewayconfig.SessionRecordingSegmentConfig{}).(*asciicastRecorder)
				if err := r.WriteHeader(AsciicastHeader{Version: 2, Width: 80, Height: 24}); err != nil {
					b.Fatal(err)
				}

				for range events {
					if err := r.WriteOutputEvent(terminalOutput); err != nil {
						b.Fatal(err)
					}
				}

				r.Stop()
			}
		})
	}
}
