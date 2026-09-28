// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func RunCommand(cmd *exec.Cmd) ([]byte, error) {
	output, err := cmd.CombinedOutput()
	if err != nil {
		command := strings.Join(cmd.Args, " ")

		return output, fmt.Errorf("%q failed with error %q: %w", command, string(output), err)
	}

	return output, nil
}

const (
	// A failed pull discards its progress, so there is nothing to gain by waiting out containerd's
	// 30s response-header timeout. The cap must still clear a slow but healthy pull, because a
	// retry restarts the download from scratch.
	pullAttemptTimeout = 15 * time.Second
	pullAttempts       = 3
	pullRetryInterval  = 2 * time.Second
)

// ensureDockerImage makes image available in the local image store. It skips the pull when the
// image is already there, and retries a failed pull because registries fail intermittently.
func ensureDockerImage(t *testing.T, image string) {
	t.Helper()

	// `docker pull` contacts the registry even when the image is already present, so this check avoids an
	// unnecessary network request.
	//
	// #nosec G204 -- image is supplied by test code
	if _, err := RunCommand(exec.Command("docker", "image", "inspect", image)); err == nil {
		return
	}

	var pullErr error

	for attempt := range pullAttempts {
		if attempt > 0 {
			time.Sleep(pullRetryInterval)
		}

		attemptCtx, cancel := context.WithTimeout(t.Context(), pullAttemptTimeout)

		// #nosec G204 -- image is supplied by test code
		_, pullErr = RunCommand(exec.CommandContext(attemptCtx, "docker", "pull", image))

		cancel()

		if pullErr == nil {
			return
		}

		// A killed process reports only "signal: killed", so name the deadline that killed it.
		if errors.Is(attemptCtx.Err(), context.DeadlineExceeded) {
			pullErr = fmt.Errorf("timed out after %s: %w", pullAttemptTimeout, pullErr)
		}

		t.Logf("Pull of %s failed: %v", image, pullErr)
	}

	require.NoError(t, pullErr, "failed to pull docker image %s", image)
}
