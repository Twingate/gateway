// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package wshijacker

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/remotecommand"

	"gateway/internal/sessionrecorder"
)

type mockConn struct {
	readData  []byte
	writeData *bytes.Buffer
	closed    bool
}

func (m *mockConn) Read(b []byte) (int, error) {
	if len(m.readData) == 0 {
		return 0, nil
	}

	n := copy(b, m.readData)
	m.readData = m.readData[n:]

	return n, nil
}

func (m *mockConn) Write(b []byte) (int, error) {
	if m.writeData == nil {
		m.writeData = new(bytes.Buffer)
	}

	return m.writeData.Write(b)
}

func (m *mockConn) Close() error {
	m.closed = true

	return nil
}

func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(_ time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(_ time.Time) error { return nil }

type mockRecorder struct {
	headerWritten bool
	header        sessionrecorder.AsciicastHeader
	events        [][]byte
	resizeEvents  []sessionrecorder.ResizeMsg
	stopped       bool
}

func (m *mockRecorder) WriteHeader(h sessionrecorder.AsciicastHeader) error {
	m.header = h
	m.headerWritten = true

	return nil
}

func (m *mockRecorder) WriteOutputEvent(data []byte) error {
	m.events = append(m.events, data)

	return nil
}

func (m *mockRecorder) WriteResizeEvent(width, height int) error {
	m.resizeEvents = append(m.resizeEvents, sessionrecorder.ResizeMsg{Width: width, Height: height})

	return nil
}

func (m *mockRecorder) Stop() {
	m.stopped = true
}

func (m *mockRecorder) IsHeaderWritten() bool {
	return m.headerWritten
}

type WebSocketMessage struct {
	Bytes   []byte // raw bytes of the websocket frame
	Payload []byte // the payload of the websocket frame
}

func splitIntoN(data []byte, n int) [][]byte {
	totalLen := len(data)
	slices := make([][]byte, n)

	for i := range n {
		start := i * totalLen / n
		end := (i + 1) * totalLen / n
		slices[i] = data[start:end]
	}

	return slices
}

var controlCloseMessage = WebSocketMessage{
	Bytes: []byte{
		// Close Control Frame with "done" payload: (0x88, 0x06, 0x03, 0xe8, 0x64, 0x6f, 0x6e, 0x65)
		// 0x88: FIN=1 (final frame), Opcode=0x8 (Close Frame)
		// 0x06: Mask=0 (not masked), Payload Length=6 bytes
		// 0x03, 0xE8: Close Status Code (1000: Normal Closure)
		// 0x64, 0x6f, 0x6e, 0x65: UTF-8 for "done"
		0x88, 0x06, 0x03, 0xe8, 0x64, 0x6f, 0x6e, 0x65,
	},
	Payload: []byte{
		0x64, 0x6f, 0x6e, 0x65, // UTF-8 for "done"
	},
}

var controlPingMessage = WebSocketMessage{
	Bytes: []byte{
		// PING Control Frame with "ping!" payload: (0x89, 0x05, 0x70, 0x69, 0x6e, 0x67, 0x21)
		// 0x89: FIN=1 (final frame), Opcode=0x9 (PING Frame)
		// 0x05: Mask=0 (not masked), Payload Length=5 bytes
		// 0x70, 0x69, 0x6e, 0x67, 0x21: UTF-8 for "ping!"
		0x89, 0x05, 0x70, 0x69, 0x6e, 0x67, 0x21,
	},
	Payload: []byte{
		0x70, 0x69, 0x6e, 0x67, 0x21, // UTF-8 for "ping!"
	},
}

func TestConn_Read(t *testing.T) {
	var dataResizeMessage = WebSocketMessage{
		Bytes: []byte{
			// Data Message Frame: (0x82, 0x19, 0x4, 0x7b, ...)
			// 0x82: FIN=1 (final fragment), Opcode=0x2 (Binary Frame)
			// 0x19: Mask=0 (not masked), Payload Length=25 bytes
			// Payload: 0x04 (StreamResize) + "{"width":40,"height":80}"
			// 0x4, 0x7b, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22, 0x3a, 0x34, 0x30,
			// 0x2c, 0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3a, 0x38, 0x30, 0x7d
			0x82, 0x19, 0x4, 0x7b, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22, 0x3a, 0x34, 0x30,
			0x2c, 0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3a, 0x38, 0x30, 0x7d,
		},
		Payload: []byte{
			0x7b, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22, 0x3a, 0x34, 0x30, 0x2c,
			0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3a, 0x38, 0x30, 0x7d,
		},
	}

	var dataResizeFragment1 = WebSocketMessage{
		Bytes: []byte{
			// First Fragment of Data Message: (0x02, 0x0C, ...)
			// 0x02: FIN=0 (NOT final fragment), Opcode=0x2 (Binary Frame - starts the message)
			// 0x0C: Mask=0 (not masked), Payload Length=12 bytes
			// Payload: 0x04 (StreamResize) + "{"width":40"
			0x02, 0x0C, 0x04, 0x7b, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22, 0x3a, 0x34, 0x30,
		},
		Payload: []byte{
			0x7b, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22, 0x3a, 0x34, 0x30,
		},
	}

	var dataResizeFragment2 = WebSocketMessage{
		Bytes: []byte{
			// Second Fragment of Data Message: (0x80, 0x0D, ...)
			// 0x80: FIN=1 (final fragment), Opcode=0x0 (Continuation Frame - ends the message)
			// 0x0D: Mask=0 (not masked), Payload Length=13 bytes
			// Payload: 0x04 (StreamResize) + ","height":80}"
			0x80, 0x0E, 0x04, 0x2c, 0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3a, 0x38, 0x30, 0x7d,
		},
		Payload: []byte{
			0x2c, 0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3a, 0x38, 0x30, 0x7d,
		},
	}

	tests := []struct {
		name         string
		readInputs   [][]byte
		resizeWidth  int
		resizeHeight int
		expectResize bool
	}{
		// TEST DATA MESSAGES
		{
			name: "resize message, 1 read",
			readInputs: [][]byte{
				dataResizeMessage.Bytes,
			},
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
		{
			name:         "resize message, 3 reads",
			readInputs:   splitIntoN(dataResizeMessage.Bytes, 3),
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
		{
			name: "resize message, 2 fragments, 1 read",
			readInputs: [][]byte{
				append(dataResizeFragment1.Bytes, dataResizeFragment2.Bytes...),
			},
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
		{
			name:         "resize message, 2 fragments, 3 reads",
			readInputs:   splitIntoN(append(dataResizeFragment1.Bytes, dataResizeFragment2.Bytes...), 3),
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
		// TEST CONTROL MESSAGES
		{
			name: "control message(PING), 1 read",
			readInputs: [][]byte{
				controlPingMessage.Bytes,
			},
			expectResize: false,
		},
		{
			name:         "control message(CLOSE), 3 reads",
			readInputs:   splitIntoN(controlCloseMessage.Bytes, 3),
			expectResize: false,
		},
		// TEST MULTIPLE MESSAGES
		{
			name: "2 resize messages, 1 read",
			readInputs: [][]byte{
				append(dataResizeMessage.Bytes, dataResizeMessage.Bytes...),
			},
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
		{
			name:         "2 resize messages, 3 reads",
			readInputs:   splitIntoN(append(dataResizeMessage.Bytes, dataResizeMessage.Bytes...), 3),
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
		// TEST MIXED MESSAGE TYPES: DATA AND CONTROL
		{
			name: "resize message + control message(PING), 1 read",
			readInputs: [][]byte{
				append(dataResizeMessage.Bytes, controlPingMessage.Bytes...),
			},
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
		{
			name: "control message(PING) + resize message, 1 read",
			readInputs: [][]byte{
				append(controlPingMessage.Bytes, dataResizeMessage.Bytes...),
			},
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
		// TEST INTERLEAVED MESSAGES
		{
			name: "resize message + control message(PING) + resize message, 1 read",
			readInputs: [][]byte{
				append(append(dataResizeMessage.Bytes, controlPingMessage.Bytes...), dataResizeMessage.Bytes...),
			},
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
		{
			name: "resize message fragment 1 + control message(PING) + resize message fragment 2, 3 reads",
			readInputs: splitIntoN(append(append(dataResizeFragment1.Bytes, controlPingMessage.Bytes...),
				dataResizeFragment2.Bytes...), 3),
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
		{
			name: "resize message fragment 1 + control message(PING) + resize message fragment 2, 5 reads",
			readInputs: splitIntoN(append(append(dataResizeFragment1.Bytes,
				controlPingMessage.Bytes...), dataResizeFragment2.Bytes...), 5),
			resizeWidth:  40,
			resizeHeight: 80,
			expectResize: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := &mockConn{}
			mr := &mockRecorder{}
			c := NewConn(mc, mr, sessionrecorder.AsciicastHeader{}, true).(*conn)

			expectedBytes := make([]byte, 0)

			totalLength := 0
			for _, chunk := range tt.readInputs {
				totalLength += len(chunk)
				expectedBytes = append(expectedBytes, chunk...)
			}

			readBytes := make([]byte, 0)

			for _, input := range tt.readInputs {
				mc.readData = append(mc.readData, input...)
				buf := make([]byte, len(input))

				n, err := c.Read(buf)
				require.NoError(t, err)

				assert.Equal(t, len(input), n)

				readBytes = append(readBytes, buf...)
			}

			assert.Equal(t, expectedBytes, readBytes)

			// Check if first resize was processed
			if tt.expectResize {
				select {
				case <-c.readFirstResize:
					// Channel should be closed
				default:
					t.Error("Expected readFirstResize channel to be closed")
				}

				assert.Equal(t, tt.resizeWidth, c.asciicastHeader.Width)
				assert.Equal(t, tt.resizeHeight, c.asciicastHeader.Height)
			}
		})
	}
}

func TestConn_Write(t *testing.T) {
	var dataMessageNoFragmentStdOut = WebSocketMessage{
		Bytes: []byte{
			// Data Message Frame: (0x82, 0x23, 0x01, 0x7b, ...)
			// 0x82: FIN=1 (final fragment), Opcode=0x2 (Binary Frame)
			// 0x23: Mask=0 (not masked), Payload Length=35 bytes
			// Payload: 0x01 (StreamStdOut) + {"metadata":{},"status":"Success"}
			// 0x01, 0x7b, 0x22, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x22, 0x3a, 0x7b, 0x7d, 0x2c, 0x22, 0x73,
			// 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x3a, 0x22, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x7d
			0x82, 0x23, 0x01, 0x7b, 0x22, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
			0x61, 0x22, 0x3a, 0x7b, 0x7d, 0x2c, 0x22, 0x73, 0x74, 0x61, 0x74, 0x75,
			0x73, 0x22, 0x3a, 0x22, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x7d,
		},
		Payload: []byte{
			0x7b, 0x22, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
			0x61, 0x22, 0x3a, 0x7b, 0x7d, 0x2c, 0x22, 0x73, 0x74, 0x61, 0x74, 0x75,
			0x73, 0x22, 0x3a, 0x22, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x7d,
		},
	}

	var dataMessageNoFragmentStdErr = WebSocketMessage{
		Bytes: []byte{
			// Data Message Frame: (0x82, 0x23, 0x01, 0x7b, ...)
			// 0x82: FIN=1 (final fragment), Opcode=0x2 (Binary Frame)
			// 0x23: Mask=0 (not masked), Payload Length=35 bytes
			// Payload: 0x02 (StreamStdErr) + {"metadata":{},"status":"Success"}
			// 0x01, 0x7b, 0x22, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x22, 0x3a, 0x7b, 0x7d, 0x2c, 0x22, 0x73,
			// 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x3a, 0x22, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x7d
			0x82, 0x23, 0x02, 0x7b, 0x22, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
			0x61, 0x22, 0x3a, 0x7b, 0x7d, 0x2c, 0x22, 0x73, 0x74, 0x61, 0x74, 0x75,
			0x73, 0x22, 0x3a, 0x22, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x7d,
		},
		Payload: []byte{
			0x7b, 0x22, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
			0x61, 0x22, 0x3a, 0x7b, 0x7d, 0x2c, 0x22, 0x73, 0x74, 0x61, 0x74, 0x75,
			0x73, 0x22, 0x3a, 0x22, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x7d,
		},
	}

	var dataMessageStdOutFragment1 = WebSocketMessage{
		Bytes: []byte{
			// First Fragment of Data Message: (0x02, 0x12, ...)
			// 0x02: FIN=0 (NOT final fragment), Opcode=0x2 (Binary Frame)
			// 0x12: Mask=0, Payload Length=18 bytes
			// Payload: 0x01 (StreamStdOut) + {"metadata":{},"s
			0x02, 0x11, 0x01, 0x7b, 0x22, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x22, 0x3a, 0x7b, 0x7d, 0x2c, 0x22,
		},
		Payload: []byte{
			0x7b, 0x22, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x22, 0x3a, 0x7b, 0x7d, 0x2c, 0x22,
		},
	}

	var dataMessageStdOutFragment2 = WebSocketMessage{
		Bytes: []byte{
			// Second Fragment of Data Message: (0x80, 0x13, ...)
			// 0x80: FIN=1 (final fragment), Opcode=0x0 (Continuation Frame)
			// 0x13: Mask=0, Payload Length=19 bytes (0x01 prefix + remaining 18 bytes of original payload)
			// Payload: 0x01 (StreamStdOut) + tatus":"Success"}
			0x80, 0x13, 0x01, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x3a, 0x22, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x7d,
		},
		Payload: []byte{
			0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x3a, 0x22, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x7d,
		},
	}

	tests := []struct {
		name            string
		header          sessionrecorder.AsciicastHeader
		writeInputs     [][]byte
		expectedRecords [][]byte
		expectResize    bool
		hasTerminal     bool
	}{
		// TEST DATA MESSAGES
		{
			name:            "single data message, stdout",
			header:          sessionrecorder.AsciicastHeader{Version: 2, Width: 10, Height: 10},
			writeInputs:     [][]byte{dataMessageNoFragmentStdOut.Bytes},
			expectedRecords: [][]byte{dataMessageNoFragmentStdOut.Payload},
			expectResize:    true,
			hasTerminal:     true,
		},
		{
			name:            "single data message, stderr",
			header:          sessionrecorder.AsciicastHeader{Version: 2, Width: 10, Height: 10},
			writeInputs:     [][]byte{dataMessageNoFragmentStdErr.Bytes},
			expectedRecords: [][]byte{dataMessageNoFragmentStdErr.Payload},
			expectResize:    true,
			hasTerminal:     true,
		},
		{
			name:            "single data message, 3 writes",
			header:          sessionrecorder.AsciicastHeader{Version: 2, Width: 20, Height: 30},
			writeInputs:     splitIntoN(dataMessageNoFragmentStdOut.Bytes, 3),
			expectedRecords: [][]byte{dataMessageNoFragmentStdOut.Payload},
			expectResize:    true,
			hasTerminal:     true,
		},
		{
			name:   "single data message, 2 fragments, 1 write",
			header: sessionrecorder.AsciicastHeader{Version: 2, Width: 20, Height: 30},
			writeInputs: [][]byte{
				append(dataMessageStdOutFragment1.Bytes, dataMessageStdOutFragment2.Bytes...),
			},
			expectedRecords: [][]byte{
				append(dataMessageStdOutFragment1.Payload, dataMessageStdOutFragment2.Payload...),
			},
			expectResize: true,
			hasTerminal:  true,
		},
		{
			name:        "single data message, 2 fragments, 3 writes",
			header:      sessionrecorder.AsciicastHeader{Version: 2, Width: 20, Height: 30},
			writeInputs: splitIntoN(append(dataMessageStdOutFragment1.Bytes, dataMessageStdOutFragment2.Bytes...), 3),
			expectedRecords: [][]byte{
				append(dataMessageStdOutFragment1.Payload, dataMessageStdOutFragment2.Payload...),
			},
			expectResize: true,
			hasTerminal:  true,
		},
		{
			name:        "single data message, 2 fragments, 3 writes, no terminal",
			header:      sessionrecorder.AsciicastHeader{Version: 2, Width: 20, Height: 30},
			writeInputs: splitIntoN(append(dataMessageStdOutFragment1.Bytes, dataMessageStdOutFragment2.Bytes...), 3),
			expectedRecords: [][]byte{
				append(dataMessageStdOutFragment1.Payload, dataMessageStdOutFragment2.Payload...),
			},
			expectResize: false,
			hasTerminal:  false,
		},
		// TEST CONTROL MESSAGES
		{
			name: "control message(PING), 1 write",
			writeInputs: [][]byte{
				controlPingMessage.Bytes,
			},
			expectResize: false,
			hasTerminal:  false,
		},
		{
			name:         "control message(CLOSE), 3 writes",
			writeInputs:  splitIntoN(controlCloseMessage.Bytes, 3),
			expectResize: false,
			hasTerminal:  false,
		},
		// TEST MULTIPLE MESSAGES
		{
			name:   "2 data messages, 1 write",
			header: sessionrecorder.AsciicastHeader{Version: 2, Width: 20, Height: 30},
			writeInputs: [][]byte{
				append(dataMessageNoFragmentStdOut.Bytes, dataMessageNoFragmentStdOut.Bytes...),
			},
			expectedRecords: [][]byte{
				dataMessageNoFragmentStdOut.Payload,
				dataMessageNoFragmentStdOut.Payload,
			},
			expectResize: true,
			hasTerminal:  true,
		},
		{
			name:        "2 data messages, 3 writes",
			header:      sessionrecorder.AsciicastHeader{Version: 2, Width: 5, Height: 40},
			writeInputs: splitIntoN(append(dataMessageNoFragmentStdOut.Bytes, dataMessageNoFragmentStdOut.Bytes...), 3),
			expectedRecords: [][]byte{
				dataMessageNoFragmentStdOut.Payload,
				dataMessageNoFragmentStdOut.Payload,
			},
			expectResize: true,
			hasTerminal:  true,
		},
		// TEST MIXED MESSAGE TYPES: DATA AND CONTROL
		{
			name:   "data message + control message(PING), 1 write",
			header: sessionrecorder.AsciicastHeader{Version: 2, Width: 20, Height: 30},
			writeInputs: [][]byte{
				append(dataMessageNoFragmentStdOut.Bytes, controlPingMessage.Bytes...),
			},
			expectedRecords: [][]byte{
				dataMessageNoFragmentStdOut.Payload,
			},
			expectResize: true,
			hasTerminal:  true,
		},
		{
			name:   "control message(PING) + data message, 1 write",
			header: sessionrecorder.AsciicastHeader{Version: 2, Width: 25, Height: 80},
			writeInputs: [][]byte{
				append(controlPingMessage.Bytes, dataMessageNoFragmentStdErr.Bytes...),
			},
			expectedRecords: [][]byte{
				dataMessageNoFragmentStdErr.Payload,
			},
			expectResize: true,
			hasTerminal:  true,
		},
		// TEST INTERLEAVED MESSAGES
		{
			name:   "data message + control message(PING) + data message, 1 write",
			header: sessionrecorder.AsciicastHeader{Version: 2, Width: 20, Height: 30},
			writeInputs: [][]byte{
				append(append(dataMessageNoFragmentStdOut.Bytes, controlPingMessage.Bytes...), dataMessageNoFragmentStdErr.Bytes...),
			},
			expectedRecords: [][]byte{
				dataMessageNoFragmentStdOut.Payload,
				dataMessageNoFragmentStdErr.Payload,
			},
			expectResize: true,
			hasTerminal:  true,
		},
		{
			name:   "data message fragment 1 + control message(PING) + data message fragment 2, 3 writes",
			header: sessionrecorder.AsciicastHeader{Version: 2, Width: 50, Height: 50},
			writeInputs: splitIntoN(append(append(dataMessageStdOutFragment1.Bytes, controlPingMessage.Bytes...),
				dataMessageStdOutFragment2.Bytes...), 3),
			expectedRecords: [][]byte{
				dataMessageNoFragmentStdOut.Payload,
			},
			expectResize: true,
			hasTerminal:  true,
		},
		{
			name:   "data message fragment 1 + control message(PING) + data message fragment 2, 5 writes",
			header: sessionrecorder.AsciicastHeader{Version: 2, Width: 50, Height: 50},
			writeInputs: splitIntoN(append(append(dataMessageStdOutFragment1.Bytes,
				controlPingMessage.Bytes...), dataMessageStdOutFragment2.Bytes...), 5),
			expectedRecords: [][]byte{
				dataMessageNoFragmentStdOut.Payload,
			},
			expectResize: true,
			hasTerminal:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := &mockConn{}
			mr := &mockRecorder{}
			c := NewConn(mc, mr, tt.header, tt.hasTerminal).(*conn)

			if tt.expectResize && tt.hasTerminal {
				close(c.readFirstResize)
			}

			expectedBytes := make([]byte, 0)

			totalLength := 0
			for _, chunk := range tt.writeInputs {
				totalLength += len(chunk)
				expectedBytes = append(expectedBytes, chunk...)
			}

			buf := make([]byte, 0, totalLength)
			for _, input := range tt.writeInputs {
				buf = append(buf, input...)

				bytesWritten, err := c.Write(buf)
				require.NoError(t, err)

				buf = buf[bytesWritten:]
			}

			assert.Equal(t, expectedBytes, mc.writeData.Bytes())

			assert.Equal(t, tt.header.Version, mr.header.Version)
			assert.Equal(t, tt.header.Width, mr.header.Width)
			assert.Equal(t, tt.header.Height, mr.header.Height)

			assert.Equal(t, tt.expectedRecords, mr.events)
		})
	}
}

func TestConnRead_ErrorHandling(t *testing.T) {
	mc := &mockConn{}
	mr := &mockRecorder{}
	c := NewConn(mc, mr, sessionrecorder.AsciicastHeader{}, true).(*conn)

	malformedData := []byte{0x82, 0x0, 0x4, 0x7b, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22, 0x3a, 0x34, 0x30, 0x2c, 0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3a, 0x38, 0x30, 0x7d}
	mc.readData = append(mc.readData, malformedData...)

	buf := make([]byte, len(malformedData))

	_, err := c.Read(buf)
	assert.ErrorIs(t, err, errFailedToParseWS)
}

func TestConn_Close(t *testing.T) {
	mc := &mockConn{}
	mr := &mockRecorder{}
	c := NewConn(mc, mr, sessionrecorder.AsciicastHeader{}, true).(*conn)

	err := c.Close()
	require.NoError(t, err)

	assert.True(t, mc.closed)
	assert.True(t, mr.stopped)
}

func TestConn_shouldRecordReadMessage(t *testing.T) {
	c := &conn{}

	tests := []struct {
		name     string
		streamID uint32
		want     bool
	}{
		{
			name:     "should record resize stream",
			streamID: remotecommand.StreamResize,
			want:     true,
		},
		{
			name:     "should not record stdout stream",
			streamID: remotecommand.StreamStdOut,
			want:     false,
		},
		{
			name:     "should not record stderr stream",
			streamID: remotecommand.StreamStdErr,
			want:     false,
		},
		{
			name:     "should not record stdin stream",
			streamID: remotecommand.StreamStdIn,
			want:     false,
		},
		{
			name:     "should not record error stream",
			streamID: remotecommand.StreamErr,
			want:     false,
		},
		{
			name:     "should not record unknown stream",
			streamID: 99,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &wsMessage{
				k8sStreamID: tt.streamID,
			}

			got := c.shouldRecordReadMessage(msg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConn_shouldRecordWriteMessage(t *testing.T) {
	c := &conn{}

	tests := []struct {
		name     string
		streamID uint32
		want     bool
	}{
		{
			name:     "should record stdout stream",
			streamID: remotecommand.StreamStdOut,
			want:     true,
		},
		{
			name:     "should record stderr stream",
			streamID: remotecommand.StreamStdErr,
			want:     true,
		},
		{
			name:     "should not record stdin stream",
			streamID: remotecommand.StreamStdIn,
			want:     false,
		},
		{
			name:     "should not record resize stream",
			streamID: remotecommand.StreamResize,
			want:     false,
		},
		{
			name:     "should not record error stream",
			streamID: remotecommand.StreamErr,
			want:     false,
		},
		{
			name:     "should not record unknown stream",
			streamID: 255,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &wsMessage{
				k8sStreamID: tt.streamID,
			}

			got := c.shouldRecordWriteMessage(msg)
			assert.Equal(t, tt.want, got)
		})
	}
}
