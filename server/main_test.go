package main

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hasura/gotel"
	"github.com/relychan/rely-auth/authtests"
	"github.com/relychan/rely-auth/config"
	"go.opentelemetry.io/otel"
	"gotest.tools/v3/assert"
)

func TestHasuraAuthHookHandlers(t *testing.T) {
	authtests.TestHasuraAuthHookHandlers(t, initTestServer)
}

func TestAuthWebhook(t *testing.T) {
	authtests.TestAuthWebhook(t, initTestServer)
}

func TestHasuraDDNGraphQLAuth(t *testing.T) {
	authtests.TestHasuraDDNGraphQLAuth(t)
}

func TestHasuraV2GraphQLAuth(t *testing.T) {
	authtests.TestHasuraV2GraphQLAuth(t)
}

func initTestServer(t *testing.T, configPath string) (*httptest.Server, func()) {
	t.Setenv("RELY_AUTH_CONFIG_PATH", configPath)

	envVars, err := config.LoadServerConfig()
	assert.NilError(t, err)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	exporters := &gotel.OTelExporters{
		Tracer: gotel.NewTracer("test"),
		Meter:  otel.Meter("test"),
		Logger: logger,
		Shutdown: func(_ context.Context) error {
			return nil
		},
	}

	authManager, err := config.InitAuthManager(t.Context(), envVars.GetConfigPath(), exporters)
	assert.NilError(t, err)

	router := setupRouter(envVars, authManager, exporters)
	server := httptest.NewServer(router)

	shutdown := func() {
		server.Close()
		authManager.Close()
	}

	return httptest.NewServer(router), shutdown
}
