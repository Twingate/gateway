// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sshhandler

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// bufferTap is an io.Writer spy that records everything written to it, used as a ChannelCopyPair Tap.
type bufferTap struct {
	mu   sync.Mutex
	data []byte
}

func (b *bufferTap) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.data = append(b.data, p...)

	return len(p), nil
}

func (b *bufferTap) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	return append([]byte(nil), b.data...)
}

// newChannelEnds opens one real SSH channel and returns the gateway-held end (the copier operates on
// it) and the far end the test drives.
func newChannelEnds(t *testing.T) (gateway, far ssh.Channel) {
	t.Helper()

	client, server := newSSHConnEnds(t)

	go ssh.DiscardRequests(client.requests)
	go ssh.DiscardRequests(server.requests)

	accepted := acceptChannel(t, server)

	farCh, farReqs, err := client.conn.OpenChannel("session", nil)
	require.NoError(t, err)

	go ssh.DiscardRequests(farReqs)

	g := <-accepted

	go ssh.DiscardRequests(g.requests)

	return g.channel, farCh
}

func TestChannelCopyPair_copy_BasicCopy(t *testing.T) {
	srcGateway, srcFar := newChannelEnds(t)
	dstGateway, dstFar := newChannelEnds(t)

	testData := []byte("test data1234")

	eofTriggerCh := make(chan SSHRequestHandlerFlushTrigger, 1)
	channelClosedCh := make(chan struct{}, 1)

	copyPair := &ChannelCopyPair{
		logger:          zap.NewNop(),
		Src:             srcGateway,
		Dst:             dstGateway,
		EOFTriggerCh:    eofTriggerCh,
		ChannelClosedCh: channelClosedCh,
	}

	// Far end writes the data then EOFs the source.
	go func() {
		_, _ = srcFar.Write(testData)
		_ = srcFar.CloseWrite()
	}()

	// Read the copied data off the destination far end.
	gotCh := make(chan []byte, 1)

	go func() {
		buf := make([]byte, len(testData))
		_, _ = io.ReadFull(dstFar, buf)

		gotCh <- buf
	}()

	// Respond to the EOF trigger and signal the channel fully closed.
	eofCalled := false

	go func() {
		trigger := <-eofTriggerCh
		trigger.cb()

		eofCalled = true

		close(channelClosedCh)
	}()

	copyPair.copy()

	assert.Equal(t, testData, <-gotCh)
	assert.True(t, eofCalled)
}

func TestChannelCopyPair_copy_WithTap(t *testing.T) {
	srcGateway, srcFar := newChannelEnds(t)
	dstGateway, dstFar := newChannelEnds(t)
	tap := &bufferTap{}

	testData := []byte("test data for tap")

	eofTriggerCh := make(chan SSHRequestHandlerFlushTrigger, 1)
	channelClosedCh := make(chan struct{}, 1)

	copyPair := &ChannelCopyPair{
		logger:          zap.NewNop(),
		Src:             srcGateway,
		Dst:             dstGateway,
		EOFTriggerCh:    eofTriggerCh,
		ChannelClosedCh: channelClosedCh,
		Tap:             tap,
	}

	go func() {
		_, _ = srcFar.Write(testData)
		_ = srcFar.CloseWrite()
	}()

	gotCh := make(chan []byte, 1)

	go func() {
		buf := make([]byte, len(testData))
		_, _ = io.ReadFull(dstFar, buf)

		gotCh <- buf
	}()

	go func() {
		trigger := <-eofTriggerCh
		trigger.cb()

		close(channelClosedCh)
	}()

	copyPair.copy()

	// Data is copied to the destination and captured by the tap.
	assert.Equal(t, testData, <-gotCh)
	assert.Equal(t, testData, tap.bytes())
}

func TestChannelCopyPair_copy_ShutdownTimeout(t *testing.T) {
	srcGateway, srcFar := newChannelEnds(t)
	dstGateway, dstFar := newChannelEnds(t)

	// Drain the destination so its small write never blocks.
	go io.Copy(io.Discard, dstFar) //nolint:errcheck

	eofTriggerCh := make(chan SSHRequestHandlerFlushTrigger, 1)
	channelClosedCh := make(chan struct{})

	// Temporarily reduce timeouts for testing.
	originalEOFTimeout := channelEOFTimeout
	channelEOFTimeout = 50 * time.Millisecond
	originalChannelCloseTimeout := channelCloseTimeout
	channelCloseTimeout = 50 * time.Millisecond

	defer func() {
		channelEOFTimeout = originalEOFTimeout
		channelCloseTimeout = originalChannelCloseTimeout
	}()

	copyPair := &ChannelCopyPair{
		logger:          zap.NewNop(),
		Src:             srcGateway,
		Dst:             dstGateway,
		EOFTriggerCh:    eofTriggerCh,
		ChannelClosedCh: channelClosedCh,
	}

	// Source EOFs, but no EOF-trigger response and no channel-close signal are ever given.
	go func() {
		_, _ = srcFar.Write([]byte("test"))
		_ = srcFar.CloseWrite()
	}()

	start := time.Now()

	copyPair.copy()

	elapsed := time.Since(start)

	// Both the EOF-trigger wait and the channel-close wait must have timed out.
	assert.GreaterOrEqual(t, elapsed, channelEOFTimeout+channelCloseTimeout)
	assert.Less(t, elapsed, 1*time.Second)
}

func TestBidirectionalCopier_start(t *testing.T) {
	sourceSrcGateway, sourceSrcFar := newChannelEnds(t)
	sourceDstGateway, sourceDstFar := newChannelEnds(t)
	targetSrcGateway, targetSrcFar := newChannelEnds(t)
	targetDstGateway, targetDstFar := newChannelEnds(t)

	sourceData := []byte("source data")
	targetData := []byte("target data")

	sourceEOFTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)
	sourceChannelClosed := make(chan struct{}, 1)
	targetEOFTrigger := make(chan SSHRequestHandlerFlushTrigger, 1)
	targetChannelClosed := make(chan struct{}, 1)

	copier := &BidirectionalCopier{
		logger: zap.NewNop(),
		SourceToTarget: ChannelCopyPair{
			logger:          zap.NewNop(),
			Src:             sourceSrcGateway,
			Dst:             sourceDstGateway,
			EOFTriggerCh:    sourceEOFTrigger,
			ChannelClosedCh: sourceChannelClosed,
		},
		TargetToSource: ChannelCopyPair{
			logger:          zap.NewNop(),
			Src:             targetSrcGateway,
			Dst:             targetDstGateway,
			EOFTriggerCh:    targetEOFTrigger,
			ChannelClosedCh: targetChannelClosed,
		},
	}

	// Both directions write their data then EOF.
	go func() {
		_, _ = sourceSrcFar.Write(sourceData)
		_ = sourceSrcFar.CloseWrite()
	}()
	go func() {
		_, _ = targetSrcFar.Write(targetData)
		_ = targetSrcFar.CloseWrite()
	}()

	// Read the copied data off both destination far ends.
	sourceGot := make(chan []byte, 1)

	go func() {
		buf := make([]byte, len(sourceData))
		_, _ = io.ReadFull(sourceDstFar, buf)

		sourceGot <- buf
	}()

	targetGot := make(chan []byte, 1)

	go func() {
		buf := make([]byte, len(targetData))
		_, _ = io.ReadFull(targetDstFar, buf)

		targetGot <- buf
	}()

	sourceEOFCalled := false

	go func() {
		trigger := <-sourceEOFTrigger
		trigger.cb()

		sourceEOFCalled = true

		close(sourceChannelClosed)
	}()

	targetEOFCalled := false

	go func() {
		trigger := <-targetEOFTrigger
		trigger.cb()

		targetEOFCalled = true

		close(targetChannelClosed)
	}()

	start := time.Now()
	copier.start()
	elapsed := time.Since(start)

	assert.True(t, sourceEOFCalled)
	assert.True(t, targetEOFCalled)
	assert.Less(t, elapsed, 1*time.Second)

	// Data was copied in both directions.
	assert.Equal(t, sourceData, <-sourceGot)
	assert.Equal(t, targetData, <-targetGot)
}
