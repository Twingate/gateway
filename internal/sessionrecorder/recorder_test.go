// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sessionrecorder

import (
	"encoding/json"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestRecorder_NewRecorder(t *testing.T) {
	r := NewRecorder(zap.NewNop()).(*asciicastRecorder)
	assert.NotNil(t, r, "NewRecorder should return a non-nil recording")
}

func TestRecorder_WriteOutputEvent(t *testing.T) {
	r := NewRecorder(zap.NewNop()).(*asciicastRecorder)

	err := r.WriteOutputEvent([]byte("test output"))
	require.NoError(t, err, "WriteOutputEvent should not return an error")

	assert.Len(t, r.recordedLines, 1, "Recorder should have one event")

	var event []any

	err = json.Unmarshal([]byte(r.recordedLines[0]), &event)
	require.NoError(t, err, "Event should be valid JSON")
	require.Len(t, event, 3, "Event should have three elements")

	// First element is time (float)
	_, ok := event[0].(float64)
	assert.True(t, ok, "First element should be a float (time)")

	// Second element is event type
	assert.Equal(t, "o", event[1], "Second element should be 'o' (output event)")

	// Third element is the data
	assert.Equal(t, "test output", event[2], "Third element should be the output data")
}

func TestRecorder_WriteResizeEvent(t *testing.T) {
	r := NewRecorder(zap.NewNop()).(*asciicastRecorder)

	err := r.WriteResizeEvent(80, 24)
	require.NoError(t, err, "WriteResizeEvent should not return an error")

	assert.Len(t, r.recordedLines, 1, "Recorder should have one event")

	var event []any

	err = json.Unmarshal([]byte(r.recordedLines[0]), &event)
	require.NoError(t, err, "Event should be valid JSON")
	require.Len(t, event, 3, "Event should have three elements")

	// First element is time (float)
	_, ok := event[0].(float64)
	assert.True(t, ok, "First element should be a float (time)")

	// Second element is event type
	assert.Equal(t, "r", event[1], "Second element should be 'r' (resize event)")

	// Third element is the size
	assert.Equal(t, "80x24", event[2], "Third element should be the size")
}

func TestRecorder_WriteHeader(t *testing.T) {
	r := NewRecorder(zap.NewNop()).(*asciicastRecorder)

	header := AsciicastHeader{
		Version:   2,
		Width:     80,
		Height:    24,
		Timestamp: time.Now().Unix(),
		Command:   "/bin/bash",
		User:      "testuser",
	}

	err := r.WriteHeader(header)
	require.NoError(t, err, "WriteHeader should not return an error")

	var recordedHeader AsciicastHeader

	err = json.Unmarshal([]byte(r.header), &recordedHeader)
	require.NoError(t, err, "Header should be valid JSON")
	assert.Equal(t, header, recordedHeader)
}

func TestRecorder_MultipleEvents(t *testing.T) {
	r := NewRecorder(zap.NewNop()).(*asciicastRecorder)

	header := AsciicastHeader{
		Version: 2,
		Width:   80,
		Height:  24,
	}

	// Write multiple events
	require.NoError(t, r.WriteHeader(header))
	require.NoError(t, r.WriteOutputEvent([]byte("first output")))
	require.NoError(t, r.WriteResizeEvent(100, 30))
	require.NoError(t, r.WriteOutputEvent([]byte("second output")))

	assert.Len(t, r.recordedLines, 3, "Recorder should have 3 events")

	// Validate header
	var recordedHeader AsciicastHeader

	err := json.Unmarshal([]byte(r.header), &recordedHeader)
	require.NoError(t, err)
	assert.Equal(t, header.Version, recordedHeader.Version)

	// Validate second output event
	var lastEvent []any

	err = json.Unmarshal([]byte(r.recordedLines[2]), &lastEvent)
	require.NoError(t, err)
	assert.Equal(t, "o", lastEvent[1])
	assert.Equal(t, "second output", lastEvent[2])
}

func TestRecorder_Stop(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	RegisterRecordedSessionMetrics("test", testRegistry)

	core, logs := observer.New(zap.DebugLevel)
	r := NewRecorder(zap.New(core)).(*asciicastRecorder)

	// Write an event
	require.NoError(t, r.WriteOutputEvent([]byte("test")))

	// Capture r.recordedLines before Stop
	recordingLength := len(r.recordedLines)
	assert.Equal(t, 1, recordingLength, "Recorder should have one event before Stop")

	// Stop the recording
	r.Stop()

	// Check that session recording logs are flushed
	assert.Equal(t, 1, logs.Len(), "Should have one log entry")
	log := logs.All()[0]
	assert.Equal(t, "session finished", log.Message)
	assert.Contains(t, log.ContextMap()["asciicast"], "test")
	assert.Equal(t, int64(1), log.ContextMap()["asciicast_sequence_num"])

	// Check that the duration metric is recorded
	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)
	assert.Len(t, metricFamilies, 1)
	assert.Equal(t, "test_recorded_session_duration_seconds", metricFamilies[0].GetName())

	// Try to write after stop
	err = r.WriteOutputEvent([]byte("should fail"))
	require.Error(t, err, "Writing after stop should return an error")
	assert.Contains(t, err.Error(), "recording already finished")

	// Check that nothing was added
	assert.Empty(t, r.recordedLines, "Recording length should not change after Stop")
}

func TestRecorder_PeriodicFlush(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	RegisterRecordedSessionMetrics("test", testRegistry)

	synctest.Test(t, func(t *testing.T) {
		core, logs := observer.New(zap.DebugLevel)

		r := NewRecorder(zap.New(core), WithSegmentMaxDuration(time.Minute)).(*asciicastRecorder)
		defer r.Stop()

		r.header = "header"

		// 1st interval

		// Add some data
		_ = r.writeJSON([]any{0, "o", "a"})

		// Advance time to trigger flush
		time.Sleep(time.Minute)
		synctest.Wait()

		// Check that logs were flushed
		assert.Equal(t, 1, logs.Len(), "Should have one log entry")
		log := logs.TakeAll()[0]
		assert.Equal(t, "session recording", log.Message)
		assert.Contains(t, log.ContextMap()["asciicast"], "a")
		assert.Equal(t, int64(1), log.ContextMap()["asciicast_sequence_num"])

		// 2nd interval
		// Advance time to trigger flush
		time.Sleep(time.Minute)
		synctest.Wait()

		// Check there is no logs when there is no new events
		assert.Equal(t, 0, logs.Len(), "Should have no log entries")

		// 3rd interval

		// Add some data
		_ = r.writeJSON([]any{0, "o", "b"})

		// Advance time to trigger flush
		time.Sleep(time.Minute)
		synctest.Wait()

		// Check that logs were flushed
		assert.Equal(t, 1, logs.Len(), "Should have one log entry")
		log = logs.TakeAll()[0]
		assert.Equal(t, "session recording", log.Message)
		assert.Contains(t, log.ContextMap()["asciicast"], "b")
		assert.Equal(t, int64(2), log.ContextMap()["asciicast_sequence_num"])
	})
}

func TestRecorderFlow(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	RegisterRecordedSessionMetrics("test", testRegistry)

	synctest.Test(t, func(t *testing.T) {
		r := NewRecorder(zap.NewNop()).(*asciicastRecorder)

		// Verify start time is recent
		start := time.Now()
		assert.Equal(t, start, r.start)

		// Write header
		header := AsciicastHeader{
			Version: 2,
			Width:   80,
			Height:  24,
		}
		require.NoError(t, r.WriteHeader(header))

		// Check state flag after writing header
		assert.True(t, r.IsHeaderWritten(), "state should be StartedState after WriteHeader")

		// Write some events
		require.NoError(t, r.WriteOutputEvent([]byte("output 1")))
		time.Sleep(time.Second) // Sleep to ensure time difference
		require.NoError(t, r.WriteResizeEvent(90, 30))
		time.Sleep(time.Second)
		require.NoError(t, r.WriteOutputEvent([]byte("output 2")))

		assert.Len(t, r.recordedLines, 3, "Recorder should have three events")

		// Verify timing order is correct
		var event1, event2, event3 []any

		require.NoError(t, json.Unmarshal([]byte(r.recordedLines[0]), &event1))
		require.NoError(t, json.Unmarshal([]byte(r.recordedLines[1]), &event2))
		require.NoError(t, json.Unmarshal([]byte(r.recordedLines[2]), &event3))

		assert.InDelta(t, 0, event1[0].(float64), 1e-9)
		assert.InDelta(t, 1, event2[0].(float64), 1e-9)
		assert.InDelta(t, 2, event3[0].(float64), 1e-9)

		assert.True(t, r.IsHeaderWritten(), "Header should be written")

		// Stop the recording
		r.Stop()

		assert.True(t, r.stopped, "Stopped channel should be closed after Stop")
	})
}

func TestRecorder_WriteJSON_NoFlushWhenSegmentMaxSizeIsZero(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	RegisterRecordedSessionMetrics("test", testRegistry)

	synctest.Test(t, func(t *testing.T) {
		core, logs := observer.New(zap.DebugLevel)

		r := NewRecorder(zap.New(core)).(*asciicastRecorder)
		defer r.Stop()

		r.config.segmentMaxSize = 0

		_ = r.writeJSON([]any{0, "o", "a"}) // 11 bytes

		// Wait for the flush goroutine time to process
		synctest.Wait()

		assert.Equal(t, 0, logs.Len(), "No logs should be written when segment max size is zero")
	})
}

func TestRecorder_WriteJSON_FlushLogsWhenExceedingSegmentMaxSize(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	RegisterRecordedSessionMetrics("test", testRegistry)

	synctest.Test(t, func(t *testing.T) {
		core, logs := observer.New(zap.DebugLevel)
		r := NewRecorder(zap.New(core)).(*asciicastRecorder)

		r.config.segmentMaxSize = 15
		r.header = "header"

		_ = r.writeJSON([]any{0, "o", "a"}) // 11 bytes

		// Wait for the flush goroutine time to process
		synctest.Wait()

		assert.Equal(t, 0, logs.Len(), "No logs should be written when total size is below threshold")

		_ = r.writeJSON([]any{0, "o", "b"}) // 11 bytes

		// Wait for the flush goroutine time to process
		synctest.Wait()

		assert.Equal(t, 1, logs.Len(), "One log should be written when total size exceeds threshold")

		log := logs.TakeAll()[0]
		assert.Equal(t, "session recording", log.Message)
		assert.Equal(t, int64(1), log.ContextMap()["asciicast_sequence_num"])

		_ = r.writeJSON([]any{0, "o", "c"}) // 11 bytes

		// Wait for the flush goroutine time to process
		synctest.Wait()

		assert.Equal(t, 0, logs.Len(), "No logs should be written when total size is below threshold")

		// Stop the recording should flush the logs
		r.Stop()

		assert.Equal(t, 1, logs.Len(), "One log should be written when session recording finish")

		log = logs.TakeAll()[0]
		assert.Equal(t, "session finished", log.Message)
		assert.Equal(t, int64(2), log.ContextMap()["asciicast_sequence_num"])
	})
}

func TestRecorder_WriteJSON_Error(t *testing.T) {
	r := NewRecorder(zap.NewNop()).(*asciicastRecorder)

	// Create a value that cannot be marshaled to JSON, a function
	badValue := struct {
		F func()
	}{
		F: func() {},
	}

	// This should return an error
	err := r.writeJSON(badValue)
	require.Error(t, err, "writeJSON should return error for unmarshallable value")
	assert.Contains(t, err.Error(), "failed to convert json")
}

func TestRecorder_StoreEvent_Error(t *testing.T) {
	testRegistry := prometheus.NewRegistry()
	RegisterRecordedSessionMetrics("test", testRegistry)

	r := NewRecorder(zap.NewNop()).(*asciicastRecorder)
	r.Stop()

	err := r.storeEvent("test event")
	require.Error(t, err, "storeEvent should return error when recording is finished")
	assert.Equal(t, errAlreadyFinished, err)
}
