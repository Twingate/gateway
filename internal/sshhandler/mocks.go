// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"bytes"
	"io"
	"sync"

	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/ssh"
)

// MockChannel is a mock implementation for ssh.Channel.
type MockChannel struct {
	mock.Mock

	// Channel data management
	readChan chan []byte
	data     *bytes.Buffer

	closed bool

	// Request tracking
	sendRequests []*ssh.Request

	// Thread safety
	mu sync.Mutex
}

func NewMockChannel() *MockChannel {
	return &MockChannel{
		readChan: make(chan []byte, 2048),
		data:     bytes.NewBuffer(nil),
	}
}

func (m *MockChannel) Read(data []byte) (n int, err error) {
	chunk, ok := <-m.readChan
	if !ok {
		return 0, io.EOF
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	n = copy(data, chunk)

	return n, nil
}

func (m *MockChannel) Write(data []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.data.Write(data)
}

func (m *MockChannel) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.closed {
		close(m.readChan)
		m.closed = true
	}

	if len(m.ExpectedCalls) > 0 {
		args := m.Called()

		return args.Error(0)
	}

	return nil
}

func (m *MockChannel) CloseWrite() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.ExpectedCalls) > 0 {
		args := m.Called()

		return args.Error(0)
	}

	return nil
}

func (m *MockChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	m.mu.Lock()
	m.sendRequests = append(m.sendRequests, &ssh.Request{
		Type:      name,
		WantReply: wantReply,
		Payload:   payload,
	})
	m.mu.Unlock()

	if len(m.ExpectedCalls) > 0 {
		args := m.Called(name, wantReply, payload)

		return args.Bool(0), args.Error(1)
	}

	return true, nil
}

func (m *MockChannel) Stderr() io.ReadWriter {
	if len(m.ExpectedCalls) > 0 {
		args := m.Called()

		//revive:disable-next-line:unchecked-type-assertion
		return args.Get(0).(io.ReadWriter)
	}

	return m
}

func (m *MockChannel) SetData(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data = bytes.NewBuffer(data)

	// Send the data to the read channel
	if len(data) > 0 {
		m.readChan <- data
	}
}

func (m *MockChannel) GetWrittenData() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.data.Bytes()
}

func (m *MockChannel) GetSendRequests() []*ssh.Request {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.sendRequests
}

func (m *MockChannel) TriggerEOF() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.closed {
		close(m.readChan)
		m.closed = true
	}
}

// Mock implementation for ssh.Request.
type mockSSHRequest struct {
	mock.Mock

	Type      string
	WantReply bool
	Payload   []byte
}

func (m *mockSSHRequest) GetType() string {
	return m.Type
}

func (m *mockSSHRequest) GetWantReply() bool {
	return m.WantReply
}

func (m *mockSSHRequest) GetPayload() []byte {
	return m.Payload
}

func (m *mockSSHRequest) Reply(ok bool, message []byte) error {
	args := m.Called(ok, message)

	return args.Error(0)
}
