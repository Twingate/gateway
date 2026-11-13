// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

var (
	errFailedToReceiveDownstreamMessage = errors.New("failed to receive downstream message")
	errFailedToForwardDownstreamMessage = errors.New("failed to forward downstream message")
	errFailedToReceiveUpstreamMessage   = errors.New("failed to receive upstream message")
	errFailedToForwardUpstreamMessage   = errors.New("failed to forward upstream message")
)

// relay forwards messages between the downstream and upstream until either side closes.
type relay struct {
	logger     *zap.Logger
	downstream *downstreamConn
	upstream   *pgconn.HijackedConn
	audit      *auditObserver
}

func newRelay(logger *zap.Logger, downstream *downstreamConn, upstream *pgconn.HijackedConn, audit *auditObserver) *relay {
	return &relay{logger: logger, downstream: downstream, upstream: upstream, audit: audit}
}

// serve returns nil when the session ended normally: When either side closed after a Terminate message,
// the relay was closed, or ctx was canceled.
func (r *relay) serve(ctx context.Context) error {
	group, groupCtx := errgroup.WithContext(ctx)

	// The first direction to fail cancels groupCtx, as does ctx. Closing both connections then
	// stops the other direction, whose error is only a consequence of that close.
	stop := context.AfterFunc(groupCtx, r.close)
	defer stop()

	group.Go(func() error {
		defer closeOnPanic(r.logger, r.close)

		err := r.forwardDownstreamMessages()
		r.logger.Debug("Downstream relay ended", zap.Error(err))

		return err
	})
	group.Go(func() error {
		defer closeOnPanic(r.logger, r.close)

		err := r.forwardUpstreamMessages()
		r.logger.Debug("Upstream relay ended", zap.Error(err))

		return err
	})

	err := group.Wait()

	// pgproto3 reports a closed stream as io.ErrUnexpectedEOF
	if ctx.Err() != nil || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}

	return err
}

func (r *relay) close() {
	_ = r.downstream.conn.Close()
	_ = r.upstream.Conn.Close()
}

func (r *relay) forwardDownstreamMessages() error {
	for {
		msg, err := r.downstream.backend.Receive()
		if err != nil {
			return fmt.Errorf("%w: %w", errFailedToReceiveDownstreamMessage, err)
		}

		r.audit.onDownstreamMessage(msg)

		r.upstream.Frontend.Send(msg)

		if err := r.upstream.Frontend.Flush(); err != nil {
			return fmt.Errorf("%w: %w", errFailedToForwardDownstreamMessage, err)
		}
	}
}

func (r *relay) forwardUpstreamMessages() error {
	for {
		msg, err := r.upstream.Frontend.Receive()
		if err != nil {
			return fmt.Errorf("%w: %w", errFailedToReceiveUpstreamMessage, err)
		}

		r.audit.onUpstreamMessage(msg)

		r.downstream.backend.Send(msg)

		if err := r.downstream.backend.Flush(); err != nil {
			return fmt.Errorf("%w: %w", errFailedToForwardUpstreamMessage, err)
		}
	}
}
