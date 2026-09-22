// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package wshijacker

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/websocket"
)

func TestMessage_Parse_SimpleMessage(t *testing.T) {
	// Create a simple websocket message with FIN=1, binary frame (0x2), no masking
	data := []byte{
		0x82, // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x03, // MASK=0, payload length=3
		0x01, // K8s Stream ID
		0x41, // Payload: 'A'
		0x42, // Payload: 'B'
	}

	msg := &wsMessage{}
	parsed, err := msg.Parse(data)

	require.NoError(t, err)

	assert.Equal(t, 5, parsed)
	assert.Equal(t, MessageStateFinished, msg.state)
	assert.Equal(t, uint32(1), msg.k8sStreamID)
	assert.Equal(t, []byte{0x41, 0x42}, msg.payload)
}

func TestMessage_Parse_MaskedMessage(t *testing.T) {
	// Create a masked websocket message with binary frame (0x2)
	data := []byte{
		0x82,                   // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x83,                   // MASK=1, payload length=3
		0x01, 0x02, 0x03, 0x04, // Masking key
		0x02 ^ 0x01, // K8s Stream ID XOR'd with first byte of mask
		0x41 ^ 0x02, // Payload: 'A' XOR'd with second byte of mask
		0x42 ^ 0x03, // Payload: 'B' XOR'd with third byte of mask
	}

	msg := &wsMessage{}
	parsed, err := msg.Parse(data)

	require.NoError(t, err)

	assert.Equal(t, 9, parsed)
	assert.Equal(t, MessageStateFinished, msg.state)
	assert.Equal(t, uint32(2), msg.k8sStreamID)
	assert.Equal(t, []byte{0x41, 0x42}, msg.payload)
}

func TestMessage_Parse_MediumLengthMessage(t *testing.T) {
	// Create a message with 16-bit length field (126) and binary frame (0x2)
	payload := make([]byte, 130)
	payload[0] = 0x02 // K8s Stream ID

	for i := 1; i < len(payload); i++ {
		payload[i] = byte(i % 256)
	}

	data := []byte{
		0x82,       // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x7E,       // MASK=0, payload length=126 (indicates 16-bit length follows)
		0x00, 0x82, // Extended payload length (130 bytes)
	}
	data = append(data, payload...)

	msg := &wsMessage{}
	parsed, err := msg.Parse(data)

	require.NoError(t, err)

	assert.Equal(t, len(data), parsed)
	assert.Equal(t, uint32(2), msg.k8sStreamID)
	assert.Len(t, msg.payload, 129)
}

func TestMessage_Parse_LargeLengthMessage(t *testing.T) {
	// Create a message with 64-bit length field (127) and binary frame (0x2)
	payload := make([]byte, 260)
	payload[0] = 0x03 // K8s Stream ID

	for i := 1; i < len(payload); i++ {
		payload[i] = byte(i % 256)
	}

	data := []byte{
		0x82,                                           // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x7F,                                           // MASK=0, payload length=127 (indicates 64-bit length follows)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, // Extended payload length (260 bytes)
	}
	data = append(data, payload...)

	msg := &wsMessage{}
	parsed, err := msg.Parse(data)

	require.NoError(t, err)

	assert.Equal(t, len(data), parsed)
	assert.Equal(t, uint32(3), msg.k8sStreamID)
	assert.Len(t, msg.payload, 259)
}

func TestMessage_Parse_FragmentedMessage(t *testing.T) {
	// First fragment with FIN=0, opcode=2 (binary)
	data1 := []byte{
		0x02, // FIN=0, RSV1-3=0, opcode=2 (binary)
		0x03, // MASK=0, payload length=3
		0x04, // K8s Stream ID
		0x41, // Payload: 'A'
		0x42, // Payload: 'B'
	}

	// Second fragment with FIN=1, opcode=0 (continuation)
	data2 := []byte{
		0x80, // FIN=1, RSV1-3=0, opcode=0 (continuation)
		0x03, // MASK=0, payload length=3
		0x04, // K8s Stream ID (must match)
		0x43, // Payload: 'C'
		0x44, // Payload: 'D'
	}

	msg := &wsMessage{}
	parsed1, err := msg.Parse(data1)
	require.NoError(t, err)

	assert.Equal(t, 5, parsed1)
	assert.Equal(t, MessageStateFragmented, msg.state)

	parsed2, err := msg.Parse(data2)
	require.NoError(t, err)

	assert.Equal(t, 5, parsed2)
	assert.Equal(t, MessageStateFinished, msg.state)
	assert.Equal(t, uint32(4), msg.k8sStreamID)
	assert.Equal(t, []byte{0x41, 0x42, 0x43, 0x44}, msg.payload)
}

func TestMessage_Parse_MismatchedStreamID(t *testing.T) {
	// First fragment with binary frame (0x2)
	data1 := []byte{
		0x02, // FIN=0, RSV1-3=0, opcode=2 (binary)
		0x03, // MASK=0, payload length=3
		0x04, // K8s Stream ID
		0x41, // Payload: 'A'
		0x42, // Payload: 'B'
	}

	// Second fragment with different stream ID and continuation frame (0x0)
	data2 := []byte{
		0x80, // FIN=1, RSV1-3=0, opcode=0 (continuation)
		0x03, // MASK=0, payload length=3
		0x05, // Different K8s Stream ID
		0x43, // Payload: 'C'
		0x44, // Payload: 'D'
	}

	msg := &wsMessage{}

	_, err := msg.Parse(data1)
	require.NoError(t, err)

	_, err = msg.Parse(data2)
	assert.ErrorIs(t, err, errMismatchedStreamID)
}

func TestMessage_Parse_IncompleteData(t *testing.T) {
	// Create a message but truncate the payload, using binary frame (0x2)
	data := []byte{
		0x82, // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x05, // MASK=0, payload length=5
		0x01, // K8s Stream ID
		0x41, // Only 1 byte of the 4 expected payload bytes
	}

	msg := &wsMessage{}
	parsed, err := msg.Parse(data)

	require.NoError(t, err)

	assert.Equal(t, 0, parsed)
}

func TestMessage_Parse_EmptyPayload(t *testing.T) {
	// Create a message with empty payload, using binary frame (0x2)
	data := []byte{
		0x82, // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x00, // MASK=0, payload length=0
	}

	msg := &wsMessage{}
	_, err := msg.Parse(data)

	require.ErrorIs(t, err, errPayloadEmpty)
}

func TestMessage_Parse_TooLargePayload(t *testing.T) {
	// Create a message with payload length exceeding the allowed maximum, using binary frame (0x2)
	data := []byte{
		0x82, // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x7F, // MASK=0, payload length=127 (indicates 64-bit length follows)
	}
	// Add extended payload length larger than websocket.DefaultMaxPayloadBytes
	lengthBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lengthBytes, websocket.DefaultMaxPayloadBytes+1)
	data = append(data, lengthBytes...)

	msg := &wsMessage{}
	_, err := msg.Parse(data)

	require.ErrorIs(t, err, errPayloadTooLarge)
}

func TestMessage_Parse_ControlMessagePing(t *testing.T) {
	// Create a WebSocket PING message with FIN=1, opcode=9 (PING), no masking, and a small payload
	data := []byte{
		0x89, // FIN=1, RSV1-3=0, opcode=9 (PING)
		0x03, // MASK=0, payload length=3
		0x70, // Payload: 'p' (example ping data)
		0x69, // Payload: 'i'
		0x6e, // Payload: 'n'
	}

	msg := &wsMessage{}
	parsed, err := msg.Parse(data)

	require.NoError(t, err)

	// The parsed bytes should include the first byte (FIN/opcode), second byte (mask/length),
	// For this example: 1 (0x89) + 1 (0x03) + 3 (ping data) = 6 bytes
	assert.Equal(t, len(data), parsed)
	assert.Equal(t, MessageStateFinished, msg.state)

	// For PING messages, the payload can contain data, check it matches
	expectedPayload := []byte{0x70, 0x69, 0x6e}
	assert.Equal(t, expectedPayload, msg.payload)
}

func TestMessage_Parse_ControlMessageCloseMasked(t *testing.T) {
	// For a WebSocket CLOSE frame, the payload typically consists of:
	// 1. A 2-byte status code (required, unless the payload is empty).
	// 2. An optional UTF-8 encoded application data that represents the reason for closing.
	//
	// In this test, the unmasked payload is:
	// Status Code: 1000 (0x03E8) - This signifies "Normal Closure".
	// Reason: "Bye" (ASCII bytes: 0x42, 0x79, 0x65).
	// Each byte of the unmasked payload is XORed with a byte from the masking key.
	// 0x03 ^ 0x01 = 0x02  (First byte of status code masked)
	// 0xE8 ^ 0x02 = 0xEA  (Second byte of status code masked)
	// 0x42 ^ 0x03 = 0x41  (First byte of reason "B" masked)
	// 0x79 ^ 0x04 = 0x7D  (Second byte of reason "y" masked)
	// 0x65 ^ 0x01 = 0x64  (Third byte of reason "e" masked - key wraps around to 0x01)
	data := []byte{
		0x88,                   // Byte 0: FIN=1 (final fragment), RSV1-3=0, opcode=8 (CLOSE)
		0x85,                   // Byte 1: MASK=1 (message is masked), payload length=5 (bytes that follow the masking key)
		0x01, 0x02, 0x03, 0x04, // Bytes 2-5: Masking key (4 bytes)
		0x02, // Masked payload byte 1: Represents unmasked 0x03 (Status Code MSB)
		0xEA, // Masked payload byte 2: Represents unmasked 0xE8 (Status Code LSB)
		0x41, // Masked payload byte 3: Represents unmasked 0x42 (Reason 'B')
		0x7D, // Masked payload byte 4: Represents unmasked 0x79 (Reason 'y')
		0x64, // Masked payload byte 5: Represents unmasked 0x65 (Reason 'e')
	}

	msg := &wsMessage{}
	parsed, err := msg.Parse(data)

	require.NoError(t, err)

	assert.Equal(t, len(data), parsed)
	assert.Equal(t, MessageStateFinished, msg.state)
	// For standard WebSocket control messages (like CLOSE), a K8s Stream ID is not part of the protocol.
	// Therefore, we expect msg.k8sStreamID to be its zero-value (0), indicating it's not present/applicable.
	assert.Equal(t, uint32(0), msg.k8sStreamID)

	// Expected unmasked payload: Status Code 1000 (0x03E8) and Reason "Bye"
	expectedPayload := []byte{0x03, 0xE8, 0x42, 0x79, 0x65}
	assert.Equal(t, expectedPayload, msg.payload)
}

func TestUnmask(t *testing.T) {
	testCases := []struct {
		name     string
		mask     [4]byte
		data     []byte
		expected []byte
	}{
		{
			name:     "Simple unmask",
			mask:     [4]byte{0x01, 0x02, 0x03, 0x04},
			data:     []byte{0x41 ^ 0x01, 0x42 ^ 0x02, 0x43 ^ 0x03, 0x44 ^ 0x04, 0x45 ^ 0x01},
			expected: []byte{0x41, 0x42, 0x43, 0x44, 0x45},
		},
		{
			name:     "Zero mask",
			mask:     [4]byte{0x00, 0x00, 0x00, 0x00},
			data:     []byte{0x41, 0x42, 0x43},
			expected: []byte{0x41, 0x42, 0x43},
		},
		{
			name:     "All bits mask",
			mask:     [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
			data:     []byte{0x41 ^ 0xFF, 0x42 ^ 0xFF, 0x43 ^ 0xFF},
			expected: []byte{0x41, 0x42, 0x43},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataCopy := make([]byte, len(tc.data))
			copy(dataCopy, tc.data)

			unmask(tc.mask, dataCopy)

			assert.Equal(t, tc.expected, dataCopy)
		})
	}
}

func TestIsDataFrame(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "Text Frame (opcode 0x1)",
			input:    []byte{0x81}, // FIN=1, opcode=1 (text)
			expected: true,
		},
		{
			name:     "Binary Frame (opcode 0x2)",
			input:    []byte{0x82}, // FIN=1, opcode=2 (binary)
			expected: true,
		},
		{
			name:     "Continuation Frame (opcode 0x0)",
			input:    []byte{0x00}, // FIN=0, opcode=0 (continuation)
			expected: true,
		},
		{
			name:     "Close Frame (opcode 0x8)",
			input:    []byte{0x88}, // FIN=1, opcode=8 (close)
			expected: false,
		},
		{
			name:     "Ping Frame (opcode 0x9)",
			input:    []byte{0x89}, // FIN=1, opcode=9 (ping)
			expected: false,
		},
		{
			name:     "Pong Frame (opcode 0xA)",
			input:    []byte{0x8A}, // FIN=1, opcode=A (pong)
			expected: false,
		},
		{
			name:     "Reserved Opcode (e.g., 0x3)",
			input:    []byte{0x83}, // FIN=1, opcode=3 (reserved)
			expected: false,
		},
		{
			name:     "Empty byte slice",
			input:    []byte{},
			expected: false,
		},
		{
			name:     "Nil byte slice",
			input:    nil,
			expected: false,
		},
		{
			name:     "Binary frame with more data",
			input:    []byte{0x82, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDataFrame(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestIsK8sStreamFrame(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "Text Frame (opcode 0x1)",
			input:    []byte{0x81}, // FIN=1, opcode=1 (text)
			expected: false,
		},
		{
			name:     "Binary Frame (opcode 0x2)",
			input:    []byte{0x82}, // FIN=1, opcode=2 (binary)
			expected: true,
		},
		{
			name:     "Continuation Frame (opcode 0x0)",
			input:    []byte{0x00}, // FIN=0, opcode=0 (continuation)
			expected: true,
		},
		{
			name:     "Close Frame (opcode 0x8)",
			input:    []byte{0x88}, // FIN=1, opcode=8 (close)
			expected: false,
		},
		{
			name:     "Ping Frame (opcode 0x9)",
			input:    []byte{0x89}, // FIN=1, opcode=9 (ping)
			expected: false,
		},
		{
			name:     "Pong Frame (opcode 0xA)",
			input:    []byte{0x8A}, // FIN=1, opcode=A (pong)
			expected: false,
		},
		{
			name:     "Reserved Opcode (e.g., 0x3)",
			input:    []byte{0x83}, // FIN=1, opcode=3 (reserved)
			expected: false,
		},
		{
			name:     "Empty byte slice",
			input:    []byte{},
			expected: false,
		},
		{
			name:     "Nil byte slice",
			input:    nil,
			expected: false,
		},
		{
			name:     "Binary frame with more data",
			input:    []byte{0x82, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsK8sStreamFrame(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}
