// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package wshijacker

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"k8s.io/apimachinery/pkg/util/remotecommand"

	"gateway/internal/sessionrecorder"
)

// nopRecorder discards everything, so benchmarks measure only the frame parsing and forwarding.
type nopRecorder struct {
	headerWritten bool
}

func (r *nopRecorder) WriteHeader(_ sessionrecorder.AsciicastHeader) error {
	r.headerWritten = true

	return nil
}
func (r *nopRecorder) WriteOutputEvent(_ []byte) error { return nil }
func (r *nopRecorder) WriteResizeEvent(_, _ int) error { return nil }
func (r *nopRecorder) IsHeaderWritten() bool           { return r.headerWritten }
func (r *nopRecorder) Stop()                           {}

// discardConn accepts every write.
type discardConn struct {
	mockConn
}

func (c *discardConn) Write(b []byte) (int, error) { return len(b), nil }

// loopConn serves the same bytes on every read, like a client that keeps sending input.
type loopConn struct {
	mockConn

	data []byte
}

func (c *loopConn) Read(b []byte) (int, error) { return copy(b, c.data), nil }

// newK8sFrame builds an unfragmented binary WebSocket frame carrying payload on the given
// Kubernetes stream. A non-nil mask masks the payload, as clients do.
func newK8sFrame(streamID byte, payload []byte, mask []byte) []byte {
	body := append([]byte{streamID}, payload...)

	frame := []byte{0x82}

	maskBit := byte(0)
	if mask != nil {
		maskBit = 0x80
	}

	switch {
	case len(body) < 126:
		frame = append(frame, maskBit|byte(len(body))) //nolint:gosec // G115: bounded by the case
	case len(body) <= 0xffff:
		frame = append(frame, maskBit|126)
		frame = binary.BigEndian.AppendUint16(frame, uint16(len(body))) //nolint:gosec // G115: bounded by the case
	default:
		frame = append(frame, maskBit|127)
		frame = binary.BigEndian.AppendUint64(frame, uint64(len(body)))
	}

	if mask != nil {
		frame = append(frame, mask...)
		for i := range body {
			body[i] ^= mask[i%4]
		}
	}

	return append(frame, body...)
}

var benchFrameSizes = []struct {
	name string
	size int
}{
	{name: "frame=64B", size: 64},
	{name: "frame=1KiB", size: 1024},
	{name: "frame=32KiB", size: 32 * 1024},
}

// BenchmarkConn_Write measures upstream output (stdout) flowing to the client through the recorder.
func BenchmarkConn_Write(b *testing.B) {
	for _, size := range benchFrameSizes {
		b.Run(size.name, func(b *testing.B) {
			// Several frames per write, like a buffered upstream read.
			frame := newK8sFrame(remotecommand.StreamStdOut, bytes.Repeat([]byte("x"), size.size), nil)
			data := bytes.Repeat(frame, 8)

			c := NewConn(&discardConn{}, &nopRecorder{}, sessionrecorder.AsciicastHeader{}, false)

			b.SetBytes(int64(len(data)))
			b.ReportAllocs()

			for b.Loop() {
				if _, err := c.Write(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkConn_Read measures masked client input (stdin) flowing upstream through the recorder.
func BenchmarkConn_Read(b *testing.B) {
	for _, size := range benchFrameSizes {
		b.Run(size.name, func(b *testing.B) {
			frame := newK8sFrame(remotecommand.StreamStdIn, bytes.Repeat([]byte("x"), size.size), []byte{1, 2, 3, 4})

			var underlying net.Conn = &loopConn{data: frame}

			c := NewConn(underlying, &nopRecorder{}, sessionrecorder.AsciicastHeader{}, false)
			buf := make([]byte, len(frame))

			b.SetBytes(int64(len(frame)))
			b.ReportAllocs()

			for b.Loop() {
				if _, err := c.Read(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
