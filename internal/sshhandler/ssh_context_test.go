// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func newTestSSHContext() *sshContext {
	return &sshContext{
		id:            "abc123",
		username:      "gateway",
		clientVersion: "SSH-2.0-OpenSSH_10.2",
		serverVersion: "SSH-2.0-OpenSSH_9.6",
	}
}

func Test_sshContext_baseFields(t *testing.T) {
	ctx := newTestSSHContext()

	result := ctx.baseFields()

	assert.Equal(t, map[string]any{
		"id":             "abc123",
		"username":       "gateway",
		"client_version": "SSH-2.0-OpenSSH_10.2",
		"server_version": "SSH-2.0-OpenSSH_9.6",
	}, result)
}

func Test_sshContext_withGlobalRequest(t *testing.T) {
	tests := []struct {
		name    string
		reqType string
		extra   map[string]any
		wantReq map[string]any
	}{
		{
			name:    "without extra data",
			reqType: "keepalive@openssh.com",
			wantReq: map[string]any{
				"type":   "keepalive@openssh.com",
				"source": "downstream",
				"target": "upstream",
			},
		},
		{
			name:    "with accumulated request and reply fields",
			reqType: "tcpip-forward",
			extra: map[string]any{
				"bind_address":   "0.0.0.0",
				"bind_port":      uint32(0),
				"accepted":       true,
				"allocated_port": uint32(8080),
			},
			wantReq: map[string]any{
				"type":           "tcpip-forward",
				"source":         "downstream",
				"target":         "upstream",
				"bind_address":   "0.0.0.0",
				"bind_port":      uint32(0),
				"accepted":       true,
				"allocated_port": uint32(8080),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newTestSSHContext()

			result := ctx.withGlobalRequest(tt.reqType, "downstream", "upstream", tt.extra)

			assert.Equal(t, "abc123", result["id"])
			assert.Equal(t, tt.wantReq, result["global_request"])
		})
	}
}

func Test_sshContext_withConnectionClose(t *testing.T) {
	tests := []struct {
		name           string
		channelsOpened int
	}{
		{name: "zero channels", channelsOpened: 0},
		{name: "multiple channels", channelsOpened: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newTestSSHContext()

			result := ctx.withConnectionClose(tt.channelsOpened)

			assert.Equal(t, "abc123", result["id"])
			assert.Equal(t, "gateway", result["username"])
			assert.Equal(t, "SSH-2.0-OpenSSH_10.2", result["client_version"])
			assert.Equal(t, "SSH-2.0-OpenSSH_9.6", result["server_version"])
			assert.Equal(t, tt.channelsOpened, result["channels_opened"])
		})
	}
}

func Test_sshContext_MethodsReturnIndependentMaps(t *testing.T) {
	ctx := newTestSSHContext()

	m1 := ctx.baseFields()
	m2 := ctx.baseFields()

	m1["extra"] = "mutated"

	_, exists := m2["extra"]
	assert.False(t, exists, "mutating one map should not affect another")
}

func newTestSSHChannelContext() *sshChannelContext {
	return &sshChannelContext{
		sshContext:  newTestSSHContext(),
		channelID:   "ch-1",
		channelType: "session",
		sourceLabel: "downstream",
		targetLabel: "upstream",
	}
}

func Test_sshChannelContext_baseFields(t *testing.T) {
	ctx := newTestSSHChannelContext()
	ctx.channelType = "direct-tcpip"
	ctx.extra = map[string]any{
		"destination_address": "internal.example.com",
		"destination_port":    uint32(5432),
	}

	result := ctx.baseFields()

	assert.Equal(t, "abc123", result["id"])
	assert.Equal(t, "gateway", result["username"])
	assert.Equal(t, "SSH-2.0-OpenSSH_10.2", result["client_version"])
	assert.Equal(t, "SSH-2.0-OpenSSH_9.6", result["server_version"])
	assert.Equal(t, map[string]any{
		"id":                  "ch-1",
		"type":                "direct-tcpip",
		"source":              "downstream",
		"target":              "upstream",
		"destination_address": "internal.example.com",
		"destination_port":    uint32(5432),
	}, result["channel"])
}

func Test_sshChannelContext_withRequest(t *testing.T) {
	tests := []struct {
		name    string
		reqType string
		extra   map[string]any
		wantReq map[string]any
	}{
		{
			name:    "shell request with no extra fields",
			reqType: "shell",
			extra:   map[string]any{},
			wantReq: map[string]any{
				"type":   "shell",
				"source": "downstream",
				"target": "upstream",
			},
		},
		{
			name:    "exec request with command",
			reqType: "exec",
			extra:   map[string]any{"command": "ls -la"},
			wantReq: map[string]any{
				"type":    "exec",
				"source":  "downstream",
				"target":  "upstream",
				"command": "ls -la",
			},
		},
		{
			name:    "subsystem request with name",
			reqType: "subsystem",
			extra:   map[string]any{"name": "sftp"},
			wantReq: map[string]any{
				"type":   "subsystem",
				"source": "downstream",
				"target": "upstream",
				"name":   "sftp",
			},
		},
		{
			name:    "nil extra map",
			reqType: "pty-req",
			extra:   nil,
			wantReq: map[string]any{
				"type":   "pty-req",
				"source": "downstream",
				"target": "upstream",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newTestSSHChannelContext()

			result := ctx.withRequest(tt.reqType, tt.extra)

			assert.Equal(t, "abc123", result["id"])
			assert.Equal(t, map[string]any{
				"id":     "ch-1",
				"type":   "session",
				"source": "downstream",
				"target": "upstream",
			}, result["channel"])
			assert.Equal(t, tt.wantReq, result["request"])
		})
	}
}

func Test_sshChannelContext_reversed(t *testing.T) {
	ctx := newTestSSHChannelContext()
	ctx.extra = map[string]any{"destination_address": "internal.example.com"}

	reversed := ctx.reversed()

	assert.Equal(t, "upstream", reversed.sourceLabel)
	assert.Equal(t, "downstream", reversed.targetLabel)
	assert.Equal(t, ctx.channelID, reversed.channelID)
	assert.Equal(t, ctx.channelType, reversed.channelType)
	assert.Equal(t, ctx.extra, reversed.extra)
}
