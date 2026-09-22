// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package wshijacker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"k8s.io/apimachinery/pkg/util/remotecommand"

	"gateway/internal/sessionrecorder"
)

var (
	errFailedToParseWS        = errors.New("failed to parse websocket message")
	errFailedToParseResizeMsg = errors.New("failed to parse resize message")
	errFailedToWriteResizeMsg = errors.New("failed to write resize message")
	errFailedToWriteHeader    = errors.New("failed to write header")
	errFailedToWriteRecording = errors.New("failed to write recording")
)

func NewConn(c net.Conn, recorder sessionrecorder.Recorder, asciicastHeader sessionrecorder.AsciicastHeader, sessionHasTerminal bool) net.Conn {
	return &conn{
		Conn:               c,
		readFirstResize:    make(chan struct{}, 1),
		recorder:           recorder,
		asciicastHeader:    asciicastHeader,
		sessionHasTerminal: sessionHasTerminal,
	}
}

// creating an asciicast recording of a kubernetes ssh session.
type conn struct {
	net.Conn

	recorder        sessionrecorder.Recorder        // asciicast recording
	asciicastHeader sessionrecorder.AsciicastHeader // header for the asciicast recording

	// true if the kubernetes exec is a terminal session, such as 'kubectl exec /bin/bash'
	// false if not a terminal session, such as 'kubectl exec ls'
	sessionHasTerminal bool

	// Reading from downstream
	readMutex   sync.Mutex // non-parallel read
	readMessage *wsMessage // current websocket message that is being parsed
	readBuffer  bytes.Buffer
	// For asciicast recording we need to have the starting terminal size so
	// that we can create the asciicast header, which is the metadata at the start of the recording.
	// see: https://docs.asciinema.org/manual/asciicast/v2/
	// The kubernetes subprotocol will send a StreamResize event at the start of the
	// session and we will use this first event as the terminal size for the cast header.
	// Further StreamResize events will be treated as normal resize events for the asciicast recording.
	// Once we have the first StreamResize event from downstream we can then:
	// 1. write the cast header which begins the recording
	// 2. allow upstream data to be written downstream
	readFirstResize     chan struct{} // used to signal Write() that we have the first resize event
	readFirstResizeOnce sync.Once     // only use `readFirstResize` once, and close the channel after

	// Writing to downstream
	writeMutex   sync.Mutex // non-parallel write
	writeMessage *wsMessage // current websocket message that is being parsed
	writeBuffer  bytes.Buffer
	// used to block and wait for readFirstResize to be signalled, and write the cast header only once and begin recording
	writeStartRecordingOnce sync.Once
}

func (c *conn) Read(data []byte) (int, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	bytesRead, readErr := c.Conn.Read(data)
	if readErr != nil {
		// since this connection can be a hijacked connection from the HTTP server
		// we could be dealing with a tls.Conn or some other wrapper around net.Conn, which
		// can wrap io.EOF errors, so we need to check
		if errors.Is(readErr, io.EOF) {
			readErr = io.EOF
		}
	}

	// not enough data to proceed any further
	if bytesRead == 0 {
		return 0, readErr
	}

	// copy all the data into our buffer
	c.readBuffer.Write(data[:bytesRead])

	for len(c.readBuffer.Bytes()) > 0 {
		// IsDataFrame() determines the type of websocket frame (control vs data) using the first byte of the data,
		// which drives the following logic:
		// 1. start by initializing currentMessage with an empty wsMessage
		// 2. if it's a data frame, and we have an existing message, then we are dealing with a
		// fragmented data message, so we will reuse the existing message to append and reassemble for session recording
		// 3. if it's a control frame, which cannot be fragmented, they will always use a new, empty wsMessage
		currentMessage := &wsMessage{}

		if IsDataFrame(c.readBuffer.Bytes()) {
			if c.readMessage == nil {
				c.readMessage = currentMessage // set new message for reuse
			}

			currentMessage = c.readMessage
		}

		// try to parse the message.
		bytesParsed, err := currentMessage.Parse(c.readBuffer.Bytes())

		// failed to parse, do not proceed.
		if err != nil {
			return 0, fmt.Errorf("%w: %w", errFailedToParseWS, err)
		} else if bytesParsed == 0 {
			// incomplete websocket frame, unable to parse, need more data.
			// since we didn't consume any data from trying to parse c.readBuffer,
			// we don't need to do anything other than to return the amount of
			// data we read into to c.readBuffer at the start of the function,
			// providing the caller the available data to read
			return bytesRead, nil
		}

		// fully parsed websocket frame.
		// drain it from the c.readBuffer, since the data is now
		// in the currently parsed message
		c.readBuffer.Next(bytesParsed)

		// if we don't have a fully complete websocket message (it's fragmented)
		// then we can't record it until we reassemble, so
		// continue to try to parse more data from the buffer if possible
		if currentMessage.state == MessageStateFragmented {
			continue
		}

		// finished with the current message, we don't need to hold it anymore
		if currentMessage == c.readMessage {
			c.readMessage = nil
		}

		// check if we need to record this message
		if !c.shouldRecordReadMessage(currentMessage) {
			continue
		}

		var resizeMessage sessionrecorder.ResizeMsg
		if err = json.Unmarshal(currentMessage.payload, &resizeMessage); err != nil {
			return bytesRead, fmt.Errorf("%w: %w", errFailedToParseResizeMsg, err)
		}

		// if it's the first resize, we save it for the asciicast header
		// otherwise we record it as a terminal resize event
		var firstResize bool

		c.readFirstResizeOnce.Do(func() {
			firstResize = true
		})

		if firstResize {
			// set the header terminal size and close the channel
			c.asciicastHeader.Width = resizeMessage.Width
			c.asciicastHeader.Height = resizeMessage.Height
			close(c.readFirstResize)
		} else if err := c.recorder.WriteResizeEvent(resizeMessage.Width, resizeMessage.Height); err != nil {
			return bytesRead, fmt.Errorf("%w: %w", errFailedToWriteResizeMsg, err)
		}
	}

	return bytesRead, nil
}

func (c *conn) Write(data []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	// not enough data to proceed any further
	if len(data) == 0 {
		return 0, nil
	}

	// copy all the data into our buffer
	c.writeBuffer.Write(data)

	for len(c.writeBuffer.Bytes()) > 0 {
		// IsDataFrame() determines the type of websocket frame (control vs data) using the first byte of the data,
		// which drives the following logic:
		// 1. start by initializing currentMessage with an empty wsMessage
		// 2. if it's a data frame, and we have an existing message, then we are dealing with a
		// fragmented data message, so we will reuse the existing message to append and reassemble for session recording
		// 3. if it's a control frame, which cannot be fragmented, they will always use a new, empty wsMessage
		currentMessage := &wsMessage{}

		if IsDataFrame(c.writeBuffer.Bytes()) {
			if c.writeMessage == nil {
				c.writeMessage = currentMessage // set new message for reuse
			}

			currentMessage = c.writeMessage
		}

		// try to parse the message
		bytesParsed, err := currentMessage.Parse(c.writeBuffer.Bytes())

		// failed to parse, do not proceed
		if err != nil {
			return 0, fmt.Errorf("%w: %w", errFailedToParseWS, err)
		} else if bytesParsed == 0 {
			// incomplete websocket frame, unable to parse, need more data.
			// since we didn't consume any data from trying to parse c.writeBuffer,
			// we don't need to do anything other than to return the amount of
			// data we consumed/added to c.writeBuffer at the start of the function,
			// signaling to the caller that we have accepted the data
			return len(data), nil
		}

		// fully parsed websocket frame
		// write the parsed data to the underlying net.Conn and
		// drain it from the c.writeBuffer, since the data is now
		// in the currently parsed message
		bytesWritten, writeErr := c.Conn.Write(c.writeBuffer.Bytes()[:bytesParsed])
		if writeErr != nil {
			return 0, writeErr
		}

		c.writeBuffer.Next(bytesWritten)

		// if we don't have a fully complete websocket message (it's fragmented)
		// then we can't record it until we reassemble, so
		// continue to try to parse more data from the buffer if possible
		if currentMessage.state == MessageStateFragmented {
			continue
		}

		// finished with the current message, we don't need to hold it anymore
		if currentMessage == c.writeMessage {
			c.writeMessage = nil
		}

		// check if we need to record this message
		if !c.shouldRecordWriteMessage(currentMessage) {
			continue
		}

		// on first Write() we want to block and wait for the first resize event (if terminal) so that
		// we can record the asciicast header first and then continue the flow and recording
		var waitForFirstResize bool

		c.writeStartRecordingOnce.Do(func() {
			waitForFirstResize = c.sessionHasTerminal
		})

		// check if we need to wait
		if waitForFirstResize {
			<-c.readFirstResize // blocks waiting for Read() to unblock channel
		}

		// record the asciicast header first to start the recording
		if !c.recorder.IsHeaderWritten() {
			if err := c.recorder.WriteHeader(c.asciicastHeader); err != nil {
				return 0, fmt.Errorf("%w: %w", errFailedToWriteHeader, err)
			}
		}

		// now we can write events
		if err := c.recorder.WriteOutputEvent(currentMessage.payload); err != nil {
			return 0, fmt.Errorf("%w: %w", errFailedToWriteRecording, err)
		}
	}

	return len(data), nil
}

func (c *conn) Close() error {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	c.recorder.Stop() // stop recording

	return c.Conn.Close()
}

func (c *conn) shouldRecordReadMessage(msg *wsMessage) bool {
	return msg.k8sStreamID == remotecommand.StreamResize
}

func (c *conn) shouldRecordWriteMessage(msg *wsMessage) bool {
	return msg.k8sStreamID == remotecommand.StreamStdOut ||
		msg.k8sStreamID == remotecommand.StreamStdErr
}
