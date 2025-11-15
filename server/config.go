package main

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/caarlos0/env/v11"
	"github.com/hasura/gotel"
	"github.com/relychan/gohttps"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth"
)

var errConfigPathRequired = errors.New("config path is required")

// Environment holds information of required environment variables.
type Environment struct {
	Server    gohttps.ServerConfig
	Telemetry gotel.OTLPConfig

	ConfigPath string `env:"CONFIG_PATH" envDefault:"/app/config.yaml"`
}

// GetEnvironment loads and parses environment variables.
func GetEnvironment() (Environment, error) {
	result, err := env.ParseAs[Environment]()
	if err != nil {
		return result, fmt.Errorf("failed to parse environment variables: %w", err)
	}

	if result.ConfigPath == "" {
		return result, errConfigPathRequired
	}

	return result, nil
}

// InitAuthManager initializes the auth manager from config.
func InitAuthManager(
	environment *Environment,
	logger *slog.Logger,
) (*auth.RelyAuthManager, error) {
	authConfig, err := goutils.ReadJSONOrYAMLFile[auth.RelyAuthConfig](environment.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load auth config: %w", err)
	}

	manager, err := auth.NewRelyAuthManager(authConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth manager: %w", err)
	}

	return manager, nil
}
