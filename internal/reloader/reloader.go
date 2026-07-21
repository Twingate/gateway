// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

// Package reloader watches files and reloads their backing resource on change.
package reloader

import (
	"context"
	"fmt"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/wait"
)

// Reloader watches a set of files and invokes reload whenever any of them
// changes, retrying the watch loop after transient failures.
type Reloader struct {
	name   string
	files  []string
	reload func() error
	logger *zap.Logger
}

// New creates a Reloader that watches files and calls reload on every change.
func New(name string, logger *zap.Logger, reload func() error, files ...string) *Reloader {
	return &Reloader{
		name:   name,
		files:  files,
		reload: reload,
		logger: logger,
	}
}

// Run watches the files in the background until ctx is canceled, restarting the
// watch loop after transient failures.
func (r *Reloader) Run(ctx context.Context) {
	go wait.Until(func() {
		if err := r.watch(ctx); err != nil {
			r.logger.Error(fmt.Sprintf("failed to watch %s, will retry later", r.name), zap.Error(err))
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

	if err := r.reload(); err != nil {
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
		if err := r.reload(); err != nil {
			r.logger.Error("failed to load "+r.name, zap.Error(err))
		}

		return nil
	}

	if err := watcher.Remove(event.Name); err != nil {
		r.logger.Info("failed to remove file watch, it may have been deleted", zap.Error(err))
	}

	return watcher.Add(event.Name)
}
