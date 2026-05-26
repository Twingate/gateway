// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package wshijacker

import (
	"encoding/binary"
	"errors"
	"math"

	"golang.org/x/net/websocket"
)

var (
	errPayloadLength      = errors.New("invalid payload length")
	errPayloadTooLarge    = errors.New("payload larger than allowed maximum (32Mb)")
	errPayloadEmpty       = errors.New("payload is empty")
	errMismatchedStreamID = errors.New("mismatched k8s Stream ID")
)

type messageState int

const (
	MessageStateEmpty      messageState = iota
	MessageStateFragmented              // message is fragmented
	MessageStateFinished                // message is complete
)

type wsMessage struct {
	state messageState

	// message payload, can contain payloads from multiple fragments, appended together
	payload []byte

	// kubernetes protocol stream id
	k8sStreamID uint32
}

// https://www.rfc-editor.org/rfc/rfc6455#section-5.2
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
// | |1|2|3|       |K|             |                               |
// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
// |     Extended payload length continued, if payload len == 127  |
// + - - - - - - - - - - - - - - - +-------------------------------+
// |                               |Masking-key, if MASK set to 1  |
// +-------------------------------+-------------------------------+
// | Masking-key (continued)       |          Payload Data         |
// +-------------------------------- - - - - - - - - - - - - - - - +
// :                     Payload Data continued ...                :
// + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
// |                     Payload Data continued ...                |
// +---------------------------------------------------------------+

func (message *wsMessage) Parse(data []byte) (int, error) {
	parsed, err := message.parsePayload(data)

	if parsed > uint64(math.MaxInt) {
		return 0, errPayloadLength
	}

	return int(parsed), err
}

func (message *wsMessage) parsePayload(data []byte) (uint64, error) {
	// not enough data to proceed with parsing
	if len(data) < 2 {
		return 0, nil
	}

	// MASK bit set
	var isMasked = ((data[1] & 0x80) != 0)

	// https://www.rfc-editor.org/rfc/rfc6455#section-5.2
	// Payload length:  7 bits, 7+16 bits, or 7+64 bits
	// The length of the "Payload data", in bytes: if 0-125, that is the
	// payload length.  If 126, the following 2 bytes interpreted as a
	// 16-bit unsigned integer are the payload length.  If 127, the
	// following 8 bytes interpreted as a 64-bit unsigned integer

	var maskOffset uint64

	var payloadLength uint64

	payloadLenVal := (data[1] & 0x7f) // value of 7 bit payload length field

	switch {
	case payloadLenVal < 126: // 7 bits
		maskOffset = 2
		payloadLength = uint64(payloadLenVal) // length stored in 7 bit field

	case payloadLenVal == 126: // 7 + 16 bits
		maskOffset = 4
		if len(data) < int(maskOffset) {
			return 0, nil
		}

		payloadLength = uint64(binary.BigEndian.Uint16(data[2:4])) // length stored in 16 bit field

	case payloadLenVal == 127: // 7 + 64 bits
		maskOffset = 10
		if len(data) < int(maskOffset) {
			return 0, nil
		}

		payloadLength = binary.BigEndian.Uint64(data[2:10]) // length stored in 64 bit field

	default:
		return 0, errPayloadLength
	}

	// don't allow arbitrarily large payloads, cap to websocket default max
	if payloadLength > websocket.DefaultMaxPayloadBytes {
		return 0, errPayloadTooLarge
	}

	// if masked bit is set, masking-key takes up 4 bytes before the payload
	var payloadStart = maskOffset
	if isMasked {
		payloadStart = maskOffset + 4
	}

	// incomplete data for frame, need more data
	if (payloadStart + payloadLength) > uint64(len(data)) {
		return 0, nil
	}

	// copy the payload
	payload := data[payloadStart : payloadStart+payloadLength]

	// unmask the payload if needed
	if isMasked {
		var mask [4]byte

		copy(mask[:], data[maskOffset:payloadStart])
		unmask(mask, payload)
	}

	// handle possible k8s frames which have a payload that has the
	// Stream ID prefix
	if IsK8sStreamFrame(data) {
		// must contain a payload of at least 1 byte for the Stream ID
		if len(payload) == 0 {
			return 0, errPayloadEmpty
		}

		// pull out the kubernetes Stream ID, which is stored in the
		// first byte of payload
		k8sStreamID := uint32(payload[0])
		if message.state == MessageStateFragmented && message.k8sStreamID != k8sStreamID {
			return 0, errMismatchedStreamID
		}

		message.k8sStreamID = k8sStreamID
		payload = payload[1:] // remove the k8s Stream ID byte
	}

	if (data[0] & 0x80) == 0 {
		// if FIN bit is not set, this is a fragmented message
		message.state = MessageStateFragmented
	} else {
		// otherwise, it's the final fragment as a single frame, or in a sequence of
		// websocket frames
		message.state = MessageStateFinished
	}

	// append the payload to the message
	message.payload = append(message.payload, payload...)

	// total amount of parsed bytes
	length := payloadStart + payloadLength

	return length, nil
}

// https://www.rfc-editor.org/rfc/rfc6455#section-5.3
// Octet i of the transformed data ("transformed-octet-i") is the XOR of
// octet i of the original data ("original-octet-i") with octet at index
// i modulo 4 of the masking key ("masking-key-octet-j"):
//
//	j                   = i MOD 4
//	transformed-octet-i = original-octet-i XOR masking-key-octet-j
func unmask(mask [4]byte, data []byte) {
	for i := range data {
		data[i] ^= mask[i%4]
	}
}

// IsDataFrame checks if the message opcode type can have fragmented payload, from:
// https://www.rfc-editor.org/rfc/rfc6455#section-5.2
// *  %x0 denotes a continuation frame
// *  %x1 denotes a text frame
// *  %x2 denotes a binary frame.
func IsDataFrame(b []byte) bool {
	return len(b) > 0 && ((b[0]&0xf) == 0 || (b[0]&0xf) == 1 || (b[0]&0xf) == 2)
}

// IsK8sStreamFrame checks if the message opcode type is used by Kubernetes streams:
// *  %x0 denotes a continuation frame
// *  %x2 denotes a binary frame.
func IsK8sStreamFrame(b []byte) bool {
	return len(b) > 0 && ((b[0]&0xf) == 0 || (b[0]&0xf) == 2)
}
