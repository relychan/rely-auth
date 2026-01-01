package config

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/hasura/gotel"
	"go.opentelemetry.io/otel"
	"gotest.tools/v3/assert"
)

func TestRelyAuthServerConfig_GetConfigPath(t *testing.T) {
	testCases := []struct {
		Name         string
		Config       RelyAuthServerConfig
		ExpectedPath string
	}{
		{
			Name: "custom_path",
			Config: RelyAuthServerConfig{
				ConfigPath: "/custom/path/auth.yaml",
			},
			ExpectedPath: "/custom/path/auth.yaml",
		},
		{
			Name:         "default_path",
			Config:       RelyAuthServerConfig{},
			ExpectedPath: "/etc/rely-auth/auth.yaml",
		},
		{
			Name: "empty_string_path",
			Config: RelyAuthServerConfig{
				ConfigPath: "",
			},
			ExpectedPath: "/etc/rely-auth/auth.yaml",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := tc.Config.GetConfigPath()
			assert.Equal(t, tc.ExpectedPath, result)
		})
	}
}

func TestLoadServerConfig_FromEnv(t *testing.T) {
	// Test loading from environment variables only
	t.Setenv("RELY_AUTH_CONFIG_PATH", "/test/path/auth.yaml")
	t.Setenv("RELY_AUTH_SERVER_CONFIG_PATH", "")

	config, err := LoadServerConfig()
	assert.NilError(t, err)
	assert.Assert(t, config != nil)
	assert.Equal(t, "/test/path/auth.yaml", config.ConfigPath)
	assert.Equal(t, "rely-auth", config.Telemetry.ServiceName)
}

func TestLoadServerConfig_DefaultServiceName(t *testing.T) {
	// Clear any existing env vars
	t.Setenv("RELY_AUTH_SERVER_CONFIG_PATH", "")
	t.Setenv("RELY_AUTH_CONFIG_PATH", "")

	config, err := LoadServerConfig()
	assert.NilError(t, err)
	assert.Assert(t, config != nil)
	assert.Equal(t, "rely-auth", config.Telemetry.ServiceName)
}

func TestLoadServerConfig_FromFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "server-config.yaml")

	configContent := `
server:
  logLevel: DEBUG
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	assert.NilError(t, err)

	t.Setenv("RELY_AUTH_SERVER_CONFIG_PATH", configPath)

	config, err := LoadServerConfig()
	assert.NilError(t, err)
	assert.Assert(t, config != nil)
	// ConfigPath will use the default value as handled by GetConfigPath()
	assert.Equal(t, "/etc/rely-auth/auth.yaml", config.GetConfigPath())
	// ServiceName will be set to default "rely-auth" if empty
	assert.Equal(t, "rely-auth", config.Telemetry.ServiceName)
	assert.Equal(t, "DEBUG", config.Server.LogLevel)
}

func TestLoadServerConfig_InvalidFile(t *testing.T) {
	t.Setenv("RELY_AUTH_SERVER_CONFIG_PATH", "/nonexistent/path/config.yaml")

	_, err := LoadServerConfig()
	assert.ErrorContains(t, err, "failed to load RELY_AUTH_SERVER_CONFIG_PATH")
}

func TestLoadServerConfig_EnvOverridesFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "server-config.yaml")

	configContent := `
server:
  logLevel: WARN
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	assert.NilError(t, err)

	t.Setenv("RELY_AUTH_SERVER_CONFIG_PATH", configPath)
	t.Setenv("RELY_AUTH_CONFIG_PATH", "/env/auth.yaml")

	config, err := LoadServerConfig()
	assert.NilError(t, err)
	assert.Assert(t, config != nil)
	// Environment variable should override default value
	assert.Equal(t, "/env/auth.yaml", config.ConfigPath)
	// Service name will be set to default "rely-auth" if empty
	assert.Equal(t, "rely-auth", config.Telemetry.ServiceName)
	assert.Equal(t, "WARN", config.Server.LogLevel)
}

func TestLoadServerConfig_JSONFile(t *testing.T) {
	// Create a temporary JSON config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "server-config.json")

	configContent := `{
  "server": {
    "logLevel": "warn"
  }
}`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	assert.NilError(t, err)

	t.Setenv("RELY_AUTH_SERVER_CONFIG_PATH", configPath)

	config, err := LoadServerConfig()
	assert.NilError(t, err)
	assert.Assert(t, config != nil)
	// ConfigPath will use the default value as handled by the GetConfigPath() method
	assert.Equal(t, "/etc/rely-auth/auth.yaml", config.GetConfigPath())
	// ServiceName will be set to default "rely-auth" if empty
	assert.Equal(t, "rely-auth", config.Telemetry.ServiceName)
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
}

func newTestExporters() *gotel.OTelExporters {
	return &gotel.OTelExporters{
		Tracer: gotel.NewTracer("test"),
		Meter:  otel.Meter("test"),
		Logger: newTestLogger(),
		Shutdown: func(_ context.Context) error {
			return nil
		},
	}
}

func TestInitAuthManager_Success(t *testing.T) {
	// Create a temporary auth config file
	tmpDir := t.TempDir()
	authConfigPath := filepath.Join(tmpDir, "auth.yaml")

	authConfigContent := `
definition:
  - mode: apiKey
    tokenLocation:
      in: header
      name: Authorization
    value:
      value: "test-secret"
    sessionVariables:
      x-hasura-role:
        value: admin
`
	err := os.WriteFile(authConfigPath, []byte(authConfigContent), 0644)
	assert.NilError(t, err)

	exporters := newTestExporters()

	manager, err := InitAuthManager(context.TODO(), authConfigPath, exporters)
	assert.NilError(t, err)
	assert.Assert(t, manager != nil)
	defer manager.Close()
}

func TestInitAuthManager_InvalidConfigPath(t *testing.T) {
	exporters := newTestExporters()

	_, err := InitAuthManager(context.TODO(), "/nonexistent/auth.yaml", exporters)
	assert.ErrorContains(t, err, "failed to load auth config")
}

func TestInitAuthManager_InvalidConfig(t *testing.T) {
	// Create a temporary auth config file with invalid content
	tmpDir := t.TempDir()
	authConfigPath := filepath.Join(tmpDir, "auth.yaml")

	authConfigContent := `
definition:
  - mode: invalid
`
	err := os.WriteFile(authConfigPath, []byte(authConfigContent), 0644)
	assert.NilError(t, err)

	exporters := newTestExporters()

	_, err = InitAuthManager(context.TODO(), authConfigPath, exporters)
	assert.ErrorContains(t, err, "failed to load auth config")
}

func TestInitAuthManager_WithJWT(t *testing.T) {
	// Create a temporary auth config file with JWT mode
	tmpDir := t.TempDir()
	authConfigPath := filepath.Join(tmpDir, "auth.yaml")

	authConfigContent := `
definition:
  - mode: jwt
    tokenLocation:
      in: header
      name: Authorization
      scheme: Bearer
    key:
      algorithm: HS256
      key:
        value: "my-secret-key-for-testing-at-least-32-bytes-long"
    claimsConfig:
      locations:
        x-hasura-user-id:
          path: sub
`
	err := os.WriteFile(authConfigPath, []byte(authConfigContent), 0644)
	assert.NilError(t, err)

	exporters := newTestExporters()

	manager, err := InitAuthManager(context.TODO(), authConfigPath, exporters)
	assert.NilError(t, err)
	assert.Assert(t, manager != nil)
	defer manager.Close()
}

func TestInitAuthManager_WithWebhook(t *testing.T) {
	// Create a temporary auth config file with webhook mode
	tmpDir := t.TempDir()
	authConfigPath := filepath.Join(tmpDir, "auth.yaml")

	authConfigContent := `
definition:
  - mode: webhook
    url:
      value: "http://localhost:3000/auth"
    method: GET
    customRequest:
      headers: {}
`
	err := os.WriteFile(authConfigPath, []byte(authConfigContent), 0644)
	assert.NilError(t, err)

	exporters := newTestExporters()

	manager, err := InitAuthManager(context.TODO(), authConfigPath, exporters)
	assert.NilError(t, err)
	assert.Assert(t, manager != nil)
	defer manager.Close()
}

func TestInitAuthManager_WithMultipleModes(t *testing.T) {
	// Create a temporary auth config file with multiple auth modes
	tmpDir := t.TempDir()
	authConfigPath := filepath.Join(tmpDir, "auth.yaml")

	authConfigContent := `
definition:
  - mode: apiKey
    tokenLocation:
      in: header
      name: X-API-Key
    value:
      value: "api-secret"
    sessionVariables:
      x-hasura-role:
        value: user
  - mode: jwt
    tokenLocation:
      in: header
      name: Authorization
      scheme: Bearer
    key:
      algorithm: HS256
      key:
        value: "my-secret-key-for-testing-at-least-32-bytes-long"
    claimsConfig:
      locations:
        x-hasura-user-id:
          path: sub
  - mode: noAuth
    sessionVariables:
      x-hasura-role:
        value: anonymous
`
	err := os.WriteFile(authConfigPath, []byte(authConfigContent), 0644)
	assert.NilError(t, err)

	exporters := newTestExporters()

	manager, err := InitAuthManager(context.TODO(), authConfigPath, exporters)
	assert.NilError(t, err)
	assert.Assert(t, manager != nil)
	defer manager.Close()
}

func TestInitAuthManager_WithStrictMode(t *testing.T) {
	// Create a temporary auth config file with strict mode
	tmpDir := t.TempDir()
	authConfigPath := filepath.Join(tmpDir, "auth.yaml")

	authConfigContent := `
settings:
  strict: true
definition:
  - mode: apiKey
    tokenLocation:
      in: header
      name: Authorization
    value:
      value: "test-secret"
    sessionVariables:
      x-hasura-role:
        value: admin
`
	err := os.WriteFile(authConfigPath, []byte(authConfigContent), 0644)
	assert.NilError(t, err)

	exporters := newTestExporters()

	manager, err := InitAuthManager(context.TODO(), authConfigPath, exporters)
	assert.NilError(t, err)
	assert.Assert(t, manager != nil)
	defer manager.Close()
}

func TestInitAuthManager_JSONConfig(t *testing.T) {
	// Create a temporary JSON auth config file
	tmpDir := t.TempDir()
	authConfigPath := filepath.Join(tmpDir, "auth.json")

	authConfigContent := `{
  "definitions": [
    {
      "mode": "apiKey",
      "tokenLocation": {
      	"in": "header",
      	"name": "Authorization"
	  },
      "value": {
        "value": "json-secret"
      },
      "sessionVariables": {
        "x-hasura-role": {
          "value": "admin"
        }
      }
    }
  ]
}`
	err := os.WriteFile(authConfigPath, []byte(authConfigContent), 0644)
	assert.NilError(t, err)

	exporters := newTestExporters()

	manager, err := InitAuthManager(context.TODO(), authConfigPath, exporters)
	assert.NilError(t, err)
	assert.Assert(t, manager != nil)
	defer manager.Close()
}
