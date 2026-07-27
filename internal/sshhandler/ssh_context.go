// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"maps"

	"github.com/google/uuid"
)

// sshContext carries connection-level SSH metadata for audit logging.
type sshContext struct {
	id            string
	username      string
	clientVersion string
	serverVersion string
}

func (s *sshContext) baseFields() map[string]any {
	return map[string]any{
		"id":             s.id,
		"username":       s.username,
		"client_version": s.clientVersion,
		"server_version": s.serverVersion,
	}
}

func (s *sshContext) withGlobalRequest(reqType, source, target string, extra map[string]any) map[string]any {
	m := s.baseFields()

	req := map[string]any{
		"type":   reqType,
		"source": source,
		"target": target,
	}

	maps.Copy(req, extra)

	m["global_request"] = req

	return m
}

func (s *sshContext) withConnectionClose(channelsOpened int) map[string]any {
	m := s.baseFields()
	m["channels_opened"] = channelsOpened

	return m
}

// sshChannelContext carries channel-level SSH metadata for audit logging.
type sshChannelContext struct {
	*sshContext

	channelID   string
	channelType string
	sourceLabel string
	targetLabel string

	// extra carries channel-type-specific open details, e.g. the destination and originator of
	// a TCP/IP forwarding channel.
	extra map[string]any
}

func newSSHChannelContext(sshCtx *sshContext, channelType, sourceLabel, targetLabel string, extra map[string]any) *sshChannelContext {
	return &sshChannelContext{
		sshContext:  sshCtx,
		channelID:   uuid.New().String(),
		channelType: channelType,
		sourceLabel: sourceLabel,
		targetLabel: targetLabel,
		extra:       extra,
	}
}

func (c *sshChannelContext) baseFields() map[string]any {
	m := c.sshContext.baseFields()

	ch := map[string]any{
		"id":     c.channelID,
		"type":   c.channelType,
		"source": c.sourceLabel,
		"target": c.targetLabel,
	}

	maps.Copy(ch, c.extra)

	m["channel"] = ch

	return m
}

func (c *sshChannelContext) withRequest(reqType string, reqExtra map[string]any) map[string]any {
	m := c.baseFields()

	req := map[string]any{
		"type":   reqType,
		"source": c.sourceLabel,
		"target": c.targetLabel,
	}

	maps.Copy(req, reqExtra)

	m["request"] = req

	return m
}

// reversed returns a copy of the context with the source and target labels swapped, for logging
// traffic flowing in the opposite direction on the same channel.
func (c *sshChannelContext) reversed() *sshChannelContext {
	r := *c
	r.sourceLabel, r.targetLabel = c.targetLabel, c.sourceLabel

	return &r
}
