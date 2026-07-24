// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package reloader

import (
	"context"
	"fmt"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/wait"
)

// Reloader watches a set of files and invokes load whenever any of them
// changes, retrying the watch loop after transient failures.
type Reloader struct {
	name   string
	files  []string
	load   func() error
	logger *zap.Logger
}

// New creates a Reloader that watches files and calls load on every change.
func New(name string, logger *zap.Logger, load func() error, files ...string) *Reloader {
	return &Reloader{
		name:   name,
		files:  files,
		load:   load,
		logger: logger,
	}
}

// Run watches the files in the background until context is canceled and restarting the
// watch loop after transient failures.
func (r *Reloader) Run(ctx context.Context) {
	go wait.Until(func() {
		if err := r.watch(ctx); err != nil {
			r.logger.Error(fmt.Sprintf("Failed to watch %s, will retry later", r.name), zap.Error(err))
		}
	}, time.Minute, ctx.Done())
}

func (r *Reloader) watch(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("error creating fsnotify watcher: %w", err)
	}
	defer watcher.Close()

	for _, file := range r.files {
		if err := watcher.Add(file); err != nil {
			return fmt.Errorf("error adding watch for file %s: %w", file, err)
		}
	}

	if err := r.load(); err != nil {
		return fmt.Errorf("error loading %s: %w", r.name, err)
	}

	r.logger.Info(fmt.Sprintf("Start watching %s changes", r.name))

	for {
		select {
		case event := <-watcher.Events:
			if err := r.handleWatchEvent(event, watcher); err != nil {
				return err
			}
		case err := <-watcher.Errors:
			return fmt.Errorf("received error from watcher: %w", err)
		case <-ctx.Done():
			r.logger.Info(fmt.Sprintf("Stopped watching %s changes", r.name))

			return nil
		}
	}
}

func (r *Reloader) handleWatchEvent(event fsnotify.Event, watcher *fsnotify.Watcher) error {
	r.logger.Debug("Received watch event", zap.Any("event", event))

	if !event.Has(fsnotify.Remove) && !event.Has(fsnotify.Rename) {
		if err := r.load(); err != nil {
			r.logger.Error("Failed to load "+r.name, zap.Error(err))
		}

		return nil
	}

	if err := watcher.Remove(event.Name); err != nil {
		r.logger.Info("Failed to remove file watch, it may have been deleted", zap.Error(err))
	}

	return watcher.Add(event.Name)
}
