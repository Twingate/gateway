// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"context"
	"io"
	"os/exec"
	"strings"
)

type KubectlOptions struct {
	Kubeconfig               string
	Context                  string
	ServerURL                string
	CertificateAuthorityFile string
}

// Kubectl contains kubeconfig, context or server info to run kubectl commands.
type Kubectl struct {
	Options KubectlOptions
}

// Command is a general func to run kubectl commands.
func (k *Kubectl) Command(cmdOptions ...string) ([]byte, error) {
	return k.executeKubectl(context.Background(), nil, cmdOptions...)
}

// CommandWithInput is a general func to run kubectl commands with stdin input.
func (k *Kubectl) CommandWithInput(stdinInput string, cmdOptions ...string) ([]byte, error) {
	return k.executeKubectl(context.Background(), strings.NewReader(stdinInput), cmdOptions...)
}

func (k *Kubectl) CommandContext(ctx context.Context, cmdOptions ...string) ([]byte, error) {
	return k.executeKubectl(ctx, nil, cmdOptions...)
}

func (k *Kubectl) executeKubectl(ctx context.Context, stdIn io.Reader, cmdOptions ...string) ([]byte, error) {
	var options []string

	switch {
	case k.Options.Kubeconfig != "":
		options = []string{"--kubeconfig", k.Options.Kubeconfig}
	case k.Options.Context != "":
		options = []string{"--context", k.Options.Context}
	default:
		options = []string{
			"--server", k.Options.ServerURL,
			"--certificate-authority", k.Options.CertificateAuthorityFile,
			"--token", "void", // Bearer token is not used but kubectl CLI requires some authentication
		}
	}

	cmd := exec.CommandContext(ctx, "kubectl", append(options, cmdOptions...)...) // #nosec G204 -- kubectl is safe to use
	cmd.Stdin = stdIn

	return RunCommand(cmd)
}
