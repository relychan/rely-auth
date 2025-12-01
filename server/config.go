package main

import (
	"errors"
	"fmt"
	"slices"

	"github.com/caarlos0/env/v11"
	"github.com/hasura/gotel"
	"github.com/relychan/gohttpc"
	"github.com/relychan/gohttps"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth"
	"github.com/relychan/rely-auth/auth/authmode"
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

	if result.Telemetry.ServiceName == "" {
		result.Telemetry.ServiceName = "rely-auth"
	}

	return result, nil
}

// InitAuthManager initializes the auth manager from config.
func InitAuthManager(
	environment *Environment,
	exporters *gotel.OTelExporters,
) (*auth.RelyAuthManager, error) {
	authConfig, err := goutils.ReadJSONOrYAMLFile[auth.RelyAuthConfig](environment.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load auth config: %w", err)
	}

	if slices.ContainsFunc(authConfig.Definitions, func(def auth.RelyAuthDefinition) bool {
		mode := def.GetMode()
		// enable http client metrics if JWT or Auth webhook mode exists
		return mode == authmode.AuthModeJWT || mode == authmode.AuthModeWebhook
	}) {
		httpClientMetrics, err := gohttpc.NewHTTPClientMetrics(exporters.Meter, false)
		if err != nil {
			return nil, fmt.Errorf("failed to setup http client metrics: %w", err)
		}

		gohttpc.SetHTTPClientMetrics(httpClientMetrics)
	}

	manager, err := auth.NewRelyAuthManager(
		authConfig,
		auth.WithLogger(exporters.Logger),
		auth.WithMeter(exporters.Meter),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth manager: %w", err)
	}

	return manager, nil
}
