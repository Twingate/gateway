// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package wshijacker

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"gateway/internal/sessionrecorder"
)

var (
	errFailedToHijack = errors.New("failed to hijack")
)

type RecorderFactory func() sessionrecorder.Recorder
type ConnFactory func(net.Conn, sessionrecorder.Recorder, sessionrecorder.AsciicastHeader, bool) net.Conn

type WsHijacker struct {
	http.ResponseWriter

	request     *http.Request
	user        string
	newRecorder RecorderFactory
	newConn     ConnFactory
}

func NewHijacker(request *http.Request,
	responseWriter http.ResponseWriter,
	user string,
	newRecorder RecorderFactory,
	newConn ConnFactory) *WsHijacker {
	return &WsHijacker{
		ResponseWriter: responseWriter,
		request:        request,
		user:           user,
		newRecorder:    newRecorder,
		newConn:        newConn,
	}
}

func (h *WsHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := h.ResponseWriter.(http.Hijacker).Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errFailedToHijack, err)
	}

	// start recording, returns a wrapped conn which internally handles recording
	// the session
	wsConn := h.startRecording(conn)

	return wsConn, rw, nil
}

func (h *WsHijacker) startRecording(conn net.Conn) net.Conn {
	query := h.request.URL.Query()

	tty := strings.Join(query["tty"], "")
	command := strings.Join(query["command"], " ")

	asciicastHeader := sessionrecorder.AsciicastHeader{
		Version:   2,
		Timestamp: time.Now().Unix(),
		Command:   command,
		User:      h.user,
	}

	recorder := h.newRecorder()

	// return new wrapped connection that will record the session
	recordedConn := h.newConn(conn, recorder, asciicastHeader, tty == "true")

	return recordedConn
}
