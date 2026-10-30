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
	"github.com/jackc/pgx/v5/pgproto3"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"gateway/internal/logging"
)

var (
	errFailedToReceiveDownstreamMessage = errors.New("failed to receive downstream message")
	errFailedToForwardDownstreamMessage = errors.New("failed to forward downstream message")
	errFailedToReceiveUpstreamMessage   = errors.New("failed to receive upstream message")
	errFailedToForwardUpstreamMessage   = errors.New("failed to forward upstream message")
)

// observer sees every message before the relay forwards it. The relay calls onDownstreamMessage and
// onUpstreamMessage from separate goroutines, so the two can run at the same time. It must not
// retain, modify or block a message.
type observer interface {
	onDownstreamMessage(msg pgproto3.FrontendMessage)
	onUpstreamMessage(msg pgproto3.BackendMessage)
}

// relay forwards messages between the downstream and upstream until either side closes.
type relay struct {
	logger     logging.Logger
	downstream *downstreamConn
	upstream   *pgconn.HijackedConn
	observers  []observer
}

func newRelay(logger logging.Logger, downstream *downstreamConn, upstream *pgconn.HijackedConn, observers []observer) *relay {
	return &relay{logger: logger, downstream: downstream, upstream: upstream, observers: observers}
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
		defer closeOnPanic(r.logger.System, r.close)

		err := r.forwardDownstreamMessages()
		r.logger.System.Debug("Downstream relay ended", zap.Error(err))

		return err
	})
	group.Go(func() error {
		defer closeOnPanic(r.logger.System, r.close)

		err := r.forwardUpstreamMessages()
		r.logger.System.Debug("Upstream relay ended", zap.Error(err))

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

		for _, observer := range r.observers {
			observer.onDownstreamMessage(msg)
		}

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

		for _, observer := range r.observers {
			observer.onUpstreamMessage(msg)
		}

		r.downstream.backend.Send(msg)

		if err := r.downstream.backend.Flush(); err != nil {
			return fmt.Errorf("%w: %w", errFailedToForwardUpstreamMessage, err)
		}
	}
}
