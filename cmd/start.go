// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package cmd

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"gateway/internal/config"
	"gateway/internal/logging"
	"gateway/internal/proxy"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start Twingate Gateway",
	RunE: func(_cmd *cobra.Command, _args []string) error {
		return start()
	},
}

func start() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	logger, err := logging.New(cfg.Log)
	if err != nil {
		return fmt.Errorf("failed to create logger %w", err)
	}

	// Closing waits for a backup compression still running, so a stop does not leave it half written.
	defer logger.Close()

	p, err := newProxy(cfg, logger)
	if err != nil {
		return err
	}

	return p.Start()
}

func loadConfig() (*config.Config, error) {
	cfg, err := config.Load(viper.GetString("config"))
	if err != nil {
		return nil, fmt.Errorf("failed to load config %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate config %w", err)
	}

	return cfg, nil
}

func newProxy(cfg *config.Config, logger logging.Logger) (*proxy.Proxy, error) {
	logger.System.Debug("Gateway start called", zap.Any("config", viper.AllSettings()))

	cfg.ResolveTwingateHost(logger.System)

	registry := prometheus.NewRegistry()

	p, err := proxy.NewProxy(cfg, registry, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy %w", err)
	}

	return p, nil
}

func init() { //nolint:gochecknoinits
	viper.SetEnvPrefix("TWINGATE")
	viper.AutomaticEnv()

	flags := startCmd.Flags()
	flags.String("config", "", "Path to the configuration file")

	flags.BoolP("debug", "d", false, "Run in debug mode")

	if err := viper.BindPFlags(flags); err != nil {
		panic(fmt.Sprintf("failed to bind flags: %v", err))
	}

	rootCmd.AddCommand(startCmd)
}
