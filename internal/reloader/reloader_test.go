// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package reloader

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// recorder loads a file's content through the load callback in a
// concurrency-safe way so tests can observe reloads.
type recorder struct {
	file string

	mu      sync.RWMutex
	content string
	failNow bool
}

func (r *recorder) load() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.failNow {
		return errors.New("load failed")
	}

	data, err := os.ReadFile(r.file)
	if err != nil {
		return err
	}

	r.content = string(data)

	return nil
}

func (r *recorder) get() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.content
}

func (r *recorder) setFailNow(fail bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.failNow = fail
}

func createFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	return path
}

func TestReloadsWhenFileChanged(t *testing.T) {
	dir := t.TempDir()
	file := createFile(t, dir, "test_file", "old")
	rec := &recorder{file: file}

	New("test file", zap.NewNop(), rec.load, file).Run(t.Context())

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "old", rec.get())
	}, time.Second, 5*time.Millisecond)

	require.NoError(t, os.WriteFile(file, []byte("new"), 0600))

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "new", rec.get())
	}, time.Second, 5*time.Millisecond)
}

func TestReloadsWhenFileReplacedAtomically(t *testing.T) {
	dir := t.TempDir()
	file := createFile(t, dir, "test_file", "old")
	rec := &recorder{file: file}

	New("test file", zap.NewNop(), rec.load, file).Run(t.Context())

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "old", rec.get())
	}, time.Second, 5*time.Millisecond)

	tmp := filepath.Join(dir, "test_file.new")
	require.NoError(t, os.WriteFile(tmp, []byte("new"), 0600))
	require.NoError(t, os.Rename(tmp, file))

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "new", rec.get())
	}, time.Second, 5*time.Millisecond)
}

// TestReloadsAfterKubernetesSecretUpdate simulates the kubelet AtomicWriter update
// sequence for a projected secret volume:
//
//	mount/file -> ..data/file, ..data -> ..timestamp1; the update swaps ..data to
//	..timestamp2 and removes ..timestamp1.
func TestReloadsAfterKubernetesSecretUpdate(t *testing.T) {
	mount := t.TempDir()

	oldDataDir := filepath.Join(mount, "..timestamp1")
	require.NoError(t, os.Mkdir(oldDataDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(oldDataDir, "file"), []byte("old"), 0600))
	require.NoError(t, os.Symlink("..timestamp1", filepath.Join(mount, "..data")))
	require.NoError(t, os.Symlink(filepath.Join("..data", "file"), filepath.Join(mount, "file")))

	watched := filepath.Join(mount, "file")
	rec := &recorder{file: watched}

	New("test file", zap.NewNop(), rec.load, watched).Run(t.Context())

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "old", rec.get())
	}, time.Second, 5*time.Millisecond)

	newDataDir := filepath.Join(mount, "..timestamp2")
	require.NoError(t, os.Mkdir(newDataDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(newDataDir, "file"), []byte("new"), 0600))
	require.NoError(t, os.Symlink("..timestamp2", filepath.Join(mount, "..data_tmp")))
	require.NoError(t, os.Rename(filepath.Join(mount, "..data_tmp"), filepath.Join(mount, "..data")))
	// The symlink swap emits no fsnotify event. Removing the old data dir triggers the
	// reload and by then ..data already resolves to the new content.
	require.NoError(t, os.RemoveAll(oldDataDir))

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "new", rec.get())
	}, time.Second, 5*time.Millisecond)
}

func TestReloadsMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	fileA := createFile(t, dir, "a", "a1")
	fileB := createFile(t, dir, "b", "b1")

	var mu sync.Mutex

	loads := 0
	reload := func() error {
		mu.Lock()
		defer mu.Unlock()

		loads++

		return nil
	}

	New("a and b", zap.NewNop(), reload, fileA, fileB).Run(t.Context())

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		mu.Lock()
		defer mu.Unlock()

		assert.GreaterOrEqual(c, loads, 1)
	}, time.Second, 5*time.Millisecond)

	require.NoError(t, os.WriteFile(fileA, []byte("a2"), 0600))
	require.NoError(t, os.WriteFile(fileB, []byte("b2"), 0600))

	// Initial load plus one event per changed file.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		mu.Lock()
		defer mu.Unlock()

		assert.GreaterOrEqual(c, loads, 3)
	}, time.Second, 5*time.Millisecond)
}

func TestKeepsWatchingAfterLoadError(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)

	dir := t.TempDir()
	file := createFile(t, dir, "test_file", "old")
	rec := &recorder{file: file}

	New("test file", zap.New(core), rec.load, file).Run(t.Context())

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "old", rec.get())
	}, time.Second, 5*time.Millisecond)

	rec.setFailNow(true)
	require.NoError(t, os.WriteFile(file, []byte("bad"), 0600))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		require.NotEmpty(c, logs.FilterMessage("Failed to load test file").All())
	}, time.Second, 5*time.Millisecond)

	assert.Equal(t, "old", rec.get())

	rec.setFailNow(false)
	require.NoError(t, os.WriteFile(file, []byte("new"), 0600))

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "new", rec.get())
	}, time.Second, 5*time.Millisecond)
}

func TestRetriesWatchWhenFileRemoved(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)

	dir := t.TempDir()
	file := createFile(t, dir, "test_file", "old")
	rec := &recorder{file: file}

	New("test file", zap.New(core), rec.load, file).Run(t.Context())

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "old", rec.get())
	}, time.Second, 5*time.Millisecond)

	require.NoError(t, os.Remove(file))

	// Re-adding the watch fails because the file is gone: the watch exits and retries later.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		require.NotEmpty(c, logs.FilterMessage("Failed to watch test file, will retry later").All())
	}, time.Second, 5*time.Millisecond)
}

func TestDoesNotReloadWhenContextCanceled(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)

	dir := t.TempDir()
	file := createFile(t, dir, "test_file", "old")
	rec := &recorder{file: file}

	ctx, cancel := context.WithCancel(t.Context())
	New("test file", zap.New(core), rec.load, file).Run(ctx)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "old", rec.get())
	}, time.Second, 5*time.Millisecond)

	// Wait until the watcher confirms it stopped, so the write below cannot race an in-flight watch.
	cancel()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		require.NotEmpty(c, logs.FilterMessage("Stopped watching test file changes").All())
	}, time.Second, 5*time.Millisecond)

	require.NoError(t, os.WriteFile(file, []byte("new"), 0600))
	assert.Equal(t, "old", rec.get())
}

func TestLogsRetryWhenInitialLoadFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		core, logs := observer.New(zapcore.DebugLevel)

		dir := t.TempDir()
		file := createFile(t, dir, "test_file", "old")
		rec := &recorder{file: file, failNow: true}

		New("test file", zap.New(core), rec.load, file).Run(t.Context())

		synctest.Wait()

		all := logs.All()
		require.NotEmpty(t, all)
		assert.Equal(t, zapcore.ErrorLevel, all[0].Level)
		assert.Equal(t, "Failed to watch test file, will retry later", all[0].Message)
	})
}

func TestLogsRetryWhenFileMissing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		core, logs := observer.New(zapcore.DebugLevel)
		rec := &recorder{file: "/nonexistent/resource"}

		New("test file", zap.New(core), rec.load, "/nonexistent/resource").Run(t.Context())

		synctest.Wait()

		all := logs.All()
		require.NotEmpty(t, all)
		assert.Equal(t, zapcore.ErrorLevel, all[0].Level)
		assert.Equal(t, "Failed to watch test file, will retry later", all[0].Message)
	})
}
