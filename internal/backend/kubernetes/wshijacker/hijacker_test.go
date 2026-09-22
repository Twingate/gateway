// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package wshijacker

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/sessionrecorder"
)

type mockHijackerResponseWriter struct {
	httptest.ResponseRecorder

	conn net.Conn
	rw   *bufio.ReadWriter
	err  error
}

func (m *mockHijackerResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, m.rw, m.err
}

type mockHijackerConn struct {
	net.Conn

	writeData []byte
}

func (m *mockHijackerConn) Read(_ []byte) (n int, err error) {
	return 0, nil
}

func (m *mockHijackerConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)

	return len(b), nil
}

func (m *mockHijackerConn) Close() error {
	return nil
}

func (m *mockHijackerConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

func (m *mockHijackerConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090}
}

func (m *mockHijackerConn) SetDeadline(_ time.Time) error {
	return nil
}

func (m *mockHijackerConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (m *mockHijackerConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func mockNewConn(conn net.Conn, _ sessionrecorder.Recorder, _ sessionrecorder.AsciicastHeader, _ bool) net.Conn {
	return conn
}

func mockNewRecorder() sessionrecorder.Recorder {
	return sessionrecorder.NewRecorder(zap.NewNop())
}

func TestHijacker_New(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	user := "testuser"

	hijacker := NewHijacker(req, w, user, mockNewRecorder, mockNewConn)

	assert.NotNil(t, hijacker)
	assert.Equal(t, w, hijacker.ResponseWriter)
	assert.Equal(t, req, hijacker.request)
	assert.Equal(t, user, hijacker.user)
}

func TestHijacker_Hijack_Success(t *testing.T) {
	mockConn := &mockHijackerConn{}
	mockRW := bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(nil))
	mockResp := &mockHijackerResponseWriter{
		conn: mockConn,
		rw:   mockRW,
		err:  nil,
	}

	req := httptest.NewRequest(http.MethodGet, "/namespaces/default/pods/test-pod/exec?container=test-container&command=bash&tty=true", nil)

	hijacker := NewHijacker(req, mockResp, "testuser", mockNewRecorder, mockNewConn)

	conn, rw, err := hijacker.Hijack()

	require.NoError(t, err)
	assert.Equal(t, mockConn, conn)
	assert.Equal(t, mockRW, rw)
}

func TestHijacker_Hijack_Failure(t *testing.T) {
	mockResp := &mockHijackerResponseWriter{
		conn: nil,
		rw:   nil,
		err:  errors.New("hijack error"),
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	hijacker := NewHijacker(req, mockResp, "testuser", mockNewRecorder, mockNewConn)

	_, _, err := hijacker.Hijack()

	assert.ErrorIs(t, err, errFailedToHijack)
}

func TestHijacker_StartRecorder(t *testing.T) {
	u, _ := url.Parse("/namespaces/default/pods/test-pod/exec?container=test-container&command=bash&tty=true")
	req := &http.Request{
		URL: u,
	}

	hijacker := &WsHijacker{
		request:     req,
		user:        "testuser",
		newRecorder: mockNewRecorder,
		newConn:     mockNewConn,
	}

	mockConn := &mockHijackerConn{}
	conn := hijacker.startRecording(mockConn)

	assert.Equal(t, mockConn, conn)
}

func TestHijacker_AsciicastHeaderCreation(t *testing.T) {
	var capturedHeader sessionrecorder.AsciicastHeader

	var capturedTty bool

	newConn := func(conn net.Conn, _ sessionrecorder.Recorder, header sessionrecorder.AsciicastHeader, isTty bool) net.Conn {
		capturedHeader = header
		capturedTty = isTty

		return conn
	}

	mockConn := &mockHijackerConn{}

	u, _ := url.Parse("/namespaces/default/pods/test-pod/exec?container=test-container&command=cat&command=%2Fetc%2Fhostname&tty=true")
	req := &http.Request{
		URL: u,
	}

	hijacker := &WsHijacker{
		request:     req,
		user:        "testuser",
		newRecorder: mockNewRecorder,
		newConn:     newConn,
	}

	hijacker.startRecording(mockConn)

	assert.Equal(t, 2, capturedHeader.Version)
	assert.Equal(t, "testuser", capturedHeader.User)
	assert.Equal(t, "cat /etc/hostname", capturedHeader.Command)
	assert.True(t, capturedTty)
}
