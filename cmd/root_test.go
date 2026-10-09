// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestRootCmd_StartCommandArgs(t *testing.T) {
	startMockCalled := false
	startCmd.RunE = func(_cmd *cobra.Command, _args []string) error {
		startMockCalled = true

		return nil
	}

	cmd := rootCmd
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	cmd.SetArgs([]string{
		"start",
		"--config", "../test/data/config.yaml",
	})

	err := cmd.Execute()
	if assert.NoError(t, err) {
		assert.True(t, startMockCalled)

		assert.Equal(t, "../test/data/config.yaml", viper.GetString("config"))
	}
}
