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
	"k8s.io/apimachinery/pkg/util/wait"
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
	// A failed pull discards its progress whatever ended it, so waiting out containerd's 30s
	// response-header timeout gains nothing. The cap still has to clear a legitimate slow pull of
	// these images, which take 2-8s, because a retry starts over.
	pullAttemptTimeout = 15 * time.Second
	pullBudget         = 90 * time.Second
)

// ensureDockerImage makes image available in the local image store. It skips the pull when the
// image is already there, and retries a failed pull because registries fail intermittently.
func ensureDockerImage(t *testing.T, image string) {
	t.Helper()

	// `docker pull` contacts the registry even when the image is already present, so this check avoids an
	// unnecessary network request.
	//
	// #nosec G204 -- image is a constant defined in this package
	if _, err := RunCommand(exec.Command("docker", "image", "inspect", image)); err == nil {
		return
	}

	var pullErr error

	err := wait.PollUntilContextTimeout(t.Context(), 2*time.Second, pullBudget, true, func(ctx context.Context) (bool, error) {
		attemptCtx, cancel := context.WithTimeout(ctx, pullAttemptTimeout)
		defer cancel()

		// #nosec G204 -- image is a constant defined in this package
		if _, pullErr = RunCommand(exec.CommandContext(attemptCtx, "docker", "pull", image)); pullErr != nil {
			// The cap kills the command, so on its own the error reads only as a signal.
			if errors.Is(attemptCtx.Err(), context.DeadlineExceeded) {
				pullErr = fmt.Errorf("timed out after %s: %w", pullAttemptTimeout, pullErr)
			}

			t.Logf("Retrying pull of %s: %v", image, pullErr)

			return false, nil //nolint:nilerr
		}

		return true, nil
	})
	require.NoError(t, err, "failed to pull docker image %s: %v", image, pullErr)
}
