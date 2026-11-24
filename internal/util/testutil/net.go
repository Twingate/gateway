// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const timeout = 5 * time.Second

// TCPPipe is net.Pipe over a loopback TCP connection, whose writes are buffered instead of blocking
// until the other end reads (net.Pipe deadlocks if both ends start with a write). Both ends close
// on cleanup.
func TCPPipe(t *testing.T) (client, server net.Conn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close()

	client, err = net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	server, err = listener.Accept()
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	return client, server
}

// AssertEOF asserts the next read returns io.EOF within 5 seconds.
func AssertEOF(t *testing.T, reader io.Reader) {
	t.Helper()

	done := make(chan error, 1)

	go func() {
		_, err := reader.Read(make([]byte, 1))
		done <- err
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, io.EOF)
	case <-time.After(timeout):
		t.Fatal("timed out waiting for EOF")
	}
}
