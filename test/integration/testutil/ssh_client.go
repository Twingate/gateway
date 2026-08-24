// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"

	"gateway/internal/sshhandler"
)

var sshBanner = []byte(sshhandler.Banner)

var errMissingBanner = errors.New("output does not start with SSH banner")

type SSH struct {
	username       string
	hostname       string
	port           string
	knownHostsFile string
}

// Command is a general func to run ssh commands.
func (s *SSH) Command(cmdOptions ...string) ([]byte, error) {
	return s.executeSSH(context.Background(), cmdOptions...)
}

// CopyFileToHost is a func to copy files from SSH server to host using scp command.
func (s *SSH) CopyFileToHost(remoteDest, localDest string, cmdOptions ...string) ([]byte, error) {
	source := fmt.Sprintf("%s@%s:%s", s.username, s.hostname, remoteDest)

	return s.copy(context.Background(), source, localDest, cmdOptions...)
}

// LocalPortForward creates an ssh command with local port forwarding (-L).
// The returned cmd is prepared but not started — the caller must call cmd.Start().
func (s *SSH) LocalPortForward(ctx context.Context, localPort int, remoteHost string, remotePort int) *exec.Cmd {
	return s.portForwardCommand(ctx, "-L", fmt.Sprintf("%d:%s:%d", localPort, remoteHost, remotePort))
}

// RemotePortForward creates an ssh command with remote port forwarding (-R).
// The returned cmd is prepared but not started — the caller must call cmd.Start().
func (s *SSH) RemotePortForward(ctx context.Context, remotePort int, localHost string, localPort int) *exec.Cmd {
	return s.portForwardCommand(ctx, "-R", fmt.Sprintf("%d:%s:%d", remotePort, localHost, localPort))
}

func (s *SSH) baseOptions() []string {
	return []string{
		s.hostname,
		"-l", s.username,
		"-p", s.port,
		// Ignore the system and user ssh_config so the requests the client sends, and therefore the
		// audit logs the gateway emits, do not vary with the machine running the tests. In
		// particular `SendEnv LANG LC_*` would add an env request whenever LANG is set.
		"-F", "none",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + s.knownHostsFile,
	}
}

func (s *SSH) executeSSH(ctx context.Context, cmdOptions ...string) ([]byte, error) {
	// #nosec G204 -- ssh is safe to use
	cmd := exec.CommandContext(ctx, "ssh", append(s.baseOptions(), cmdOptions...)...)

	return runCommandAndStripBanner(cmd)
}

func (s *SSH) copy(ctx context.Context, source, target string, cmdOptions ...string) ([]byte, error) {
	var options = []string{
		"-P", s.port,
		"-F", "none",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + s.knownHostsFile,
	}

	options = append(options, cmdOptions...)

	// #nosec G204 -- scp is safe to use
	cmd := exec.CommandContext(ctx, "scp", append(options, source, target)...)

	return runCommandAndStripBanner(cmd)
}

func (s *SSH) portForwardCommand(ctx context.Context, flag, spec string) *exec.Cmd {
	options := append(s.baseOptions(),
		"-o", "ExitOnForwardFailure=yes",
		"-N",
		flag, spec,
	)

	// #nosec G204 -- ssh is safe to use
	return exec.CommandContext(ctx, "ssh", options...)
}

func runCommandAndStripBanner(cmd *exec.Cmd) ([]byte, error) {
	output, err := RunCommand(cmd)
	if err != nil {
		return nil, err
	}

	strippedOutput, err := stripSSHBanner(output)
	if err != nil {
		return nil, err
	}

	return strippedOutput, nil
}

func stripSSHBanner(output []byte) ([]byte, error) {
	if !bytes.HasPrefix(output, sshBanner) {
		return nil, errMissingBanner
	}

	return bytes.TrimPrefix(output, sshBanner), nil
}
