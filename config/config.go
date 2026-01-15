// Package config defines configurations for the auth server.
package config

import (
	"context"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/hasura/gotel"
	"github.com/relychan/gohttpc"
	"github.com/relychan/gohttps"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth"
	"github.com/relychan/rely-auth/auth/authmetrics"
	"github.com/relychan/rely-auth/auth/authmode"
)

// RelyAuthServerConfig holds information of required configurations to run the auth server.
type RelyAuthServerConfig struct {
	// Server configs.
	Server gohttps.ServerConfig `json:"server" yaml:"server"`
	// Telemetry configs.
	Telemetry gotel.OTLPConfig `json:"telemetry" yaml:"telemetry"`
	// Path of the auth config file.
	ConfigPath string `json:"configPath" yaml:"configPath" env:"RELY_AUTH_CONFIG_PATH"`
}

// GetConfigPath returns the auth config path.
func (rlsc RelyAuthServerConfig) GetConfigPath() string {
	if rlsc.ConfigPath != "" {
		return rlsc.ConfigPath
	}

	return "/etc/rely-auth/auth.yaml"
}

// LoadServerConfig loads and parses configurations for [RelyAuthServerConfig].
func LoadServerConfig() (*RelyAuthServerConfig, error) {
	var result *RelyAuthServerConfig

	var err error

	serverConfigPath := os.Getenv("RELY_AUTH_SERVER_CONFIG_PATH")
	if serverConfigPath != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		result, err = goutils.ReadJSONOrYAMLFile[RelyAuthServerConfig](ctx, serverConfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load RELY_AUTH_SERVER_CONFIG_PATH: %w", err)
		}
	} else {
		result = &RelyAuthServerConfig{}
	}

	err = env.Parse(result)
	if err != nil {
		return result, fmt.Errorf("failed to load environment variables for server config: %w", err)
	}

	if result.Telemetry.ServiceName == "" {
		result.Telemetry.ServiceName = "rely-auth"
	}

	return result, nil
}

// InitAuthManager initializes the auth manager from config.
func InitAuthManager(
	ctx context.Context,
	configPath string,
	exporters *gotel.OTelExporters,
) (*auth.RelyAuthManager, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	authConfig, err := goutils.ReadJSONOrYAMLFile[auth.RelyAuthConfig](ctx, configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load auth config: %w", err)
	}

	if slices.ContainsFunc(authConfig.Definition.Modes, func(def auth.RelyAuthMode) bool {
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

	// setup global metrics
	authMetrics, err := authmetrics.NewRelyAuthMetrics(exporters.Meter)
	if err != nil {
		return nil, fmt.Errorf("failed to setup auth metrics: %w", err)
	}

	authmetrics.SetRelyAuthMetrics(authMetrics)

	manager, err := auth.NewRelyAuthManager(
		ctx,
		authConfig,
		authmode.WithLogger(exporters.Logger),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth manager: %w", err)
	}

	return manager, nil
}
