// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sessionrecorder

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

var (
	errFailedToConvertJSON = errors.New("failed to convert json")
	errFailedToWriteEvent  = errors.New("failed to write recording")
	errAlreadyFinished     = errors.New("recording already finished")
)

var (
	recordedSessionDuration prometheus.Histogram
)

func RegisterRecordedSessionMetrics(namespace string, registry *prometheus.Registry) {
	recordedSessionDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "recorded_session_duration_seconds",
		Help:      "Duration of WebSocket session in seconds",
		Buckets:   []float64{1, 5, 10, 30, 60, 300, 600, 1800, 3600},
	})
	registry.MustRegister(recordedSessionDuration)
}

type ResizeMsg struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

type AsciicastHeader struct {
	Version   int    `json:"version"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Timestamp int64  `json:"timestamp"`
	Command   string `json:"command,omitempty"`
	User      string `json:"user"`
}

type Recorder interface {
	WriteHeader(h AsciicastHeader) error
	WriteOutputEvent(data []byte) error
	WriteResizeEvent(width int, height int) error
	IsHeaderWritten() bool
	Stop()
}

type config struct {
	// Logger to use for logging
	logger *zap.Logger

	// Max size (in bytes) limit at which the session recording is flushed.
	// If 0, there is no size limit.
	segmentMaxSize int

	// Max duration limit at which the session recording is flushed.
	// If 0, there is no duration limit.
	segmentMaxDuration time.Duration
}

type asciicastRecorder struct {
	config config

	start         time.Time
	header        string
	recordedLines []string

	// number of flushes
	flushCount int
	// ticker for periodic flush
	flushTicker *time.Ticker
	// channel to signal that a flush is needed
	flushCh chan struct{}
	// wait group for flush goroutine
	flushWg sync.WaitGroup
	// whether the recorder is stopped
	stopped bool

	mu sync.Mutex
}

func NewRecorder(logger *zap.Logger, opts ...RecorderOption) Recorder {
	r := &asciicastRecorder{
		start:         time.Now(),
		recordedLines: []string{},
		config: config{
			logger: logger,
		},
		flushCount: 0,
		flushCh:    make(chan struct{}, 1),
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.config.segmentMaxDuration > 0 {
		r.flushTicker = time.NewTicker(r.config.segmentMaxDuration)
	}

	r.flushWg.Add(1)

	go r.flushLoop()

	return r
}

type RecorderOption func(*asciicastRecorder)

func WithSegmentMaxSize(limit int) RecorderOption {
	return func(r *asciicastRecorder) {
		r.config.segmentMaxSize = limit
	}
}

func WithSegmentMaxDuration(interval time.Duration) RecorderOption {
	return func(r *asciicastRecorder) {
		r.config.segmentMaxDuration = interval
	}
}

func (r *asciicastRecorder) WriteHeader(h AsciicastHeader) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	jsonEvent, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("%w: %w", errFailedToConvertJSON, err)
	}

	r.header = string(jsonEvent)

	return nil
}

func (r *asciicastRecorder) WriteOutputEvent(data []byte) error {
	return r.writeJSON([]any{
		time.Since(r.start).Seconds(),
		"o",
		string(data)})
}

func (r *asciicastRecorder) WriteResizeEvent(width int, height int) (err error) {
	return r.writeJSON([]any{
		time.Since(r.start).Seconds(),
		"r",
		fmt.Sprintf("%dx%d", width, height)})
}

func (r *asciicastRecorder) IsHeaderWritten() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.header != ""
}

func (r *asciicastRecorder) Stop() {
	r.mu.Lock()

	if r.stopped {
		r.mu.Unlock()

		return
	}

	r.stopped = true
	duration := time.Since(r.start).Seconds()
	r.mu.Unlock()

	recordedSessionDuration.Observe(duration)

	// Signal stop and wait for flush goroutine to finish
	close(r.flushCh)
	r.flushWg.Wait()

	// Do a final flush to ensure we have a finish audit log
	r.flush(true)
}

func (r *asciicastRecorder) writeJSON(data any) error {
	jsonEvent, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("%w: %w", errFailedToConvertJSON, err)
	}

	if err := r.storeEvent(string(jsonEvent)); err != nil {
		return fmt.Errorf("%w: %w", errFailedToWriteEvent, err)
	}

	return nil
}

func (r *asciicastRecorder) storeEvent(event string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.stopped {
		return errAlreadyFinished
	}

	r.recordedLines = append(r.recordedLines, event)
	totalSize := 0

	for _, line := range r.recordedLines {
		totalSize += len(line)
	}

	if r.config.segmentMaxSize > 0 && totalSize >= r.config.segmentMaxSize {
		// Send a flush signal if there is no pending flush
		select {
		case r.flushCh <- struct{}{}:
		default:
		}
	}

	return nil
}

func (r *asciicastRecorder) flushLoop() {
	defer r.flushWg.Done()

	if r.flushTicker != nil {
		defer r.flushTicker.Stop()
	}

	var tickerCh <-chan time.Time
	if r.flushTicker != nil {
		tickerCh = r.flushTicker.C
	}

	for {
		select {
		case <-tickerCh: // if no periodic, nil channel blocks forever
			r.flush(false)
		case _, ok := <-r.flushCh:
			if !ok {
				return
			}

			r.flush(false)
		}
	}
}

func (r *asciicastRecorder) flush(isFinal bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Always flush final logs. Otherwise, flush if there is a header and some events.
	shouldFlush := isFinal || (len(r.recordedLines) > 0 && r.header != "")
	if !shouldFlush {
		return
	}

	var message string
	if isFinal {
		message = "session finished"
	} else {
		message = "session recording"
	}

	r.flushCount++
	r.config.logger.Info(message,
		zap.String("asciicast", strings.Join(append([]string{r.header}, r.recordedLines...), "\n")),
		zap.Int("asciicast_sequence_num", r.flushCount),
	)

	r.recordedLines = r.recordedLines[:0]
}
