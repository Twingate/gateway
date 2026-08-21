// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"

	"gateway/internal/sessionrecorder"
)

func AssertWhoAmI(t *testing.T, output []byte, expectedUsername string, expectedGroups []string) {
	t.Helper()

	var whoami authv1.SelfSubjectReview

	err := json.Unmarshal(output, &whoami)
	require.NoError(t, err, "failed to parse kubectl auth whoami output")

	username := whoami.Status.UserInfo.Username
	groups := whoami.Status.UserInfo.Groups

	assert.Equal(t, expectedUsername, username)
	assert.Equal(t, expectedGroups, groups)
}

func AssertGetPods(t *testing.T, output []byte) {
	t.Helper()

	var podList corev1.PodList

	err := json.Unmarshal(output, &podList)
	require.NoError(t, err, "failed to parse kubectl get pods output")

	assert.Len(t, podList.Items, 1)
	assert.Equal(t, "test-pod", podList.Items[0].Name)
}

func AssertLogsForREST(t *testing.T, logs *observer.ObservedLogs, expectedURL string, expectedUser map[string]any, expectedStatusCode int) {
	t.Helper()

	expectedLogs := logs.FilterField(zap.String("url", expectedURL)).All()
	assert.Len(t, expectedLogs, 1, "expected 1 log for URL %s, user %v", expectedURL, expectedUser)

	firstLog := expectedLogs[0]
	assert.Equal(t, "API request completed", firstLog.Message)
	assert.Equal(t, expectedUser, firstLog.ContextMap()["user"])
	assert.Subset(t, firstLog.ContextMap()["response"], map[string]any{"status_code": expectedStatusCode})
}

func AssertLogsForExecOrAttach(t *testing.T, logs *observer.ObservedLogs, expectedURL string, expectedUser map[string]any, expectedAsciicastHeader sessionrecorder.AsciicastHeader, expectedAsciicastEvents []string) {
	t.Helper()

	expectedLogs := logs.FilterField(zap.String("url", expectedURL)).All()
	assert.Len(t, expectedLogs, 2, "expected 2 logs for URL %s, user %v", expectedURL, expectedUser)

	firstLog := expectedLogs[0]
	assert.Equal(t, "session finished", firstLog.Message)
	assert.Equal(t, expectedUser, firstLog.ContextMap()["user"])

	// Validate asciicast header and event
	asciicast, ok := firstLog.ContextMap()["asciicast"].(string)
	require.True(t, ok, "asciicast should be a string")
	assertAsciicast(t, asciicast, expectedAsciicastHeader, expectedAsciicastEvents)

	secondLog := expectedLogs[1]
	assert.Equal(t, "API request completed", secondLog.Message)
	assert.Equal(t, expectedUser, secondLog.ContextMap()["user"])
	assert.Subset(t, secondLog.ContextMap()["response"], map[string]any{"status_code": http.StatusSwitchingProtocols})

	// Request and response logs must have the same request ID
	assert.Equal(t, firstLog.ContextMap()["request_id"], secondLog.ContextMap()["request_id"])
}

type SSHChannelRequestLog struct {
	Level   zapcore.Level
	Request map[string]any
}

// AssertLogsForSSHChannelRequests asserts that the observed "SSH channel request" logs are exactly
// expectedRequests, in the order the gateway logged them. Each direction is logged by its own
// goroutine, so an order across directions holds only for causally ordered requests, such as an
// exec request and the exit-status that follows it.
func AssertLogsForSSHChannelRequests(t *testing.T, logs *observer.ObservedLogs, expectedUser map[string]any, expectedRequests []SSHChannelRequestLog) {
	t.Helper()

	requestLogs := logs.FilterMessage("SSH channel request").All()
	actualRequests := make([]SSHChannelRequestLog, 0, len(requestLogs))

	for _, log := range requestLogs {
		assert.Equal(t, expectedUser, log.ContextMap()["user"])

		sshField, ok := log.ContextMap()["ssh"].(map[string]any)
		require.True(t, ok, "ssh field should be a map")

		requestField, ok := sshField["request"].(map[string]any)
		require.True(t, ok, "ssh.request field should be a map")

		actualRequests = append(actualRequests, SSHChannelRequestLog{Level: log.Level, Request: requestField})
	}

	assert.Equal(t, expectedRequests, actualRequests)
}

func AssertLogsForSSHChannel(t *testing.T, logs *observer.ObservedLogs, expectedUser, expectedChannel map[string]any) {
	t.Helper()

	channelLogs := logs.FilterMessage("SSH channel opened").All()
	require.NotEmpty(t, channelLogs, "expected at least 1 'SSH channel opened' log")

	// Find the first log entry matching expectedChannel (ignoring unrelated
	// channels such as different channel types within the same connection).
	for _, log := range channelLogs {
		sshField, ok := log.ContextMap()["ssh"].(map[string]any)
		if !ok {
			continue
		}

		channelField, ok := sshField["channel"].(map[string]any)
		if !ok {
			continue
		}

		if !matchesExpected(channelField, expectedChannel) {
			continue
		}

		assert.Equal(t, expectedUser, log.ContextMap()["user"])

		for k, v := range expectedChannel {
			assert.Equal(t, v, channelField[k], "ssh.channel.%s mismatch", k)
		}

		return
	}

	t.Errorf("no 'SSH channel opened' log matching %v", expectedChannel)
}

func AssertLogsForSSHGlobalRequest(t *testing.T, logs *observer.ObservedLogs, expectedUser, expectedGlobalRequest map[string]any) {
	t.Helper()

	globalRequestLogs := logs.FilterMessage("SSH global request").All()
	require.NotEmpty(t, globalRequestLogs, "expected at least 1 'SSH global request' log")

	// Find the first log entry matching expectedGlobalRequest (ignoring unrelated
	// global requests such as hostkeys-00@openssh.com sent by OpenSSH).
	for _, log := range globalRequestLogs {
		sshField, ok := log.ContextMap()["ssh"].(map[string]any)
		if !ok {
			continue
		}

		globalRequestField, ok := sshField["global_request"].(map[string]any)
		if !ok {
			continue
		}

		if !matchesExpected(globalRequestField, expectedGlobalRequest) {
			continue
		}

		assert.Equal(t, expectedUser, log.ContextMap()["user"])

		for k, v := range expectedGlobalRequest {
			assert.Equal(t, v, globalRequestField[k], "ssh.global_request.%s mismatch", k)
		}

		return
	}

	t.Errorf("no 'SSH global request' log matching %v", expectedGlobalRequest)
}

func matchesExpected(actual, expected map[string]any) bool {
	for k, v := range expected {
		if actual[k] != v {
			return false
		}
	}

	return true
}

func assertAsciicast(t *testing.T, asciicast string, expectedHeader sessionrecorder.AsciicastHeader, expectedEvents []string) {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(asciicast), "\n")
	expectedLines := 1 + len(expectedEvents) // Include header line and events
	require.GreaterOrEqual(t, len(lines), expectedLines, "asciicast should have at least %d lines", expectedLines)

	assertAsciicastHeader(t, lines[0], expectedHeader)

	for i, event := range expectedEvents {
		assertAsciicastEvent(t, lines[i+1], event)
	}
}

func assertAsciicastHeader(t *testing.T, headerLine string, expectedHeader sessionrecorder.AsciicastHeader) {
	t.Helper()

	var header sessionrecorder.AsciicastHeader

	err := json.Unmarshal([]byte(headerLine), &header)
	require.NoError(t, err)

	// Ignore timestamp as we cannot pinpoint the exact time in which the asciicast starts recording
	header.Timestamp = 0
	assert.Equal(t, expectedHeader, header)
}

func assertAsciicastEvent(t *testing.T, eventLine string, expectedData string) {
	t.Helper()

	var event []any

	err := json.Unmarshal([]byte(eventLine), &event)
	require.NoError(t, err)
	require.Len(t, event, 3, "event must have 3 elements")

	// First element is time (float)
	_, ok := event[0].(float64)
	assert.True(t, ok, "first element should be a float (time)")

	// Second element is event type
	assert.Equal(t, "o", event[1], "second element should be 'o'")

	// Third element is the data
	assert.Equal(t, expectedData, event[2], "third element should be %s", expectedData)
}
