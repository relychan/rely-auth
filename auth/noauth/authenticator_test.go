package noauth

import (
	"context"
	"testing"

	"github.com/hasura/goenvconf"
	"github.com/relychan/rely-auth/auth/authmode"
	"gotest.tools/v3/assert"
)

func TestNoAuth_Authenticate(t *testing.T) {
	sessionVariables := map[string]goenvconf.EnvAny{
		"x-hasura-role":          goenvconf.NewEnvAnyValue("anonymous"),
		"x-hasura-allowed-roles": goenvconf.NewEnvAnyValue([]string{"anonymous"}),
	}

	config := &RelyAuthNoAuthConfig{
		ID:               "test-noauth",
		Mode:             authmode.AuthModeNoAuth,
		SessionVariables: sessionVariables,
	}

	authenticator, err := NewNoAuth(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	assert.Equal(t, authmode.AuthModeNoAuth, authenticator.Mode())

	// Test authentication always succeeds
	result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
		Headers: map[string]string{},
	})
	assert.NilError(t, err)
	assert.Equal(t, "test-noauth", result.ID)
	assert.DeepEqual(t, map[string]any{
		"x-hasura-role":          "anonymous",
		"x-hasura-allowed-roles": []string{"anonymous"},
	}, result.SessionVariables)
}

func TestNoAuth_Close(t *testing.T) {
	config := &RelyAuthNoAuthConfig{
		Mode:             authmode.AuthModeNoAuth,
		SessionVariables: map[string]goenvconf.EnvAny{},
	}

	authenticator, err := NewNoAuth(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)

	// Test close
	err = authenticator.Close()
	assert.NilError(t, err)
}

func TestNoAuthConfig_Validate(t *testing.T) {
	config := RelyAuthNoAuthConfig{
		Mode:             authmode.AuthModeNoAuth,
		SessionVariables: map[string]goenvconf.EnvAny{},
	}

	err := config.Validate()
	assert.NilError(t, err)
}

func TestNoAuthConfig_GetMode(t *testing.T) {
	config := RelyAuthNoAuthConfig{}
	assert.Equal(t, authmode.AuthModeNoAuth, config.GetMode())
}

func TestNewNoAuthDefinition(t *testing.T) {
	sessionVars := map[string]goenvconf.EnvAny{
		"x-hasura-role": goenvconf.NewEnvAnyValue("admin"),
	}

	config := NewNoAuthDefinition(sessionVars)
	assert.Assert(t, config != nil)
	assert.DeepEqual(t, sessionVars, config.SessionVariables)
}

func TestNoAuth_Equal(t *testing.T) {
	t.Run("equal instances", func(t *testing.T) {
		sessionVars := map[string]goenvconf.EnvAny{
			"x-hasura-role": goenvconf.NewEnvAnyValue("admin"),
		}

		config1 := &RelyAuthNoAuthConfig{
			ID:               "test-id",
			Mode:             authmode.AuthModeNoAuth,
			SessionVariables: sessionVars,
		}

		config2 := &RelyAuthNoAuthConfig{
			ID:               "test-id",
			Mode:             authmode.AuthModeNoAuth,
			SessionVariables: sessionVars,
		}

		auth1, err := NewNoAuth(context.TODO(), config1, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)

		auth2, err := NewNoAuth(context.TODO(), config2, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)

		assert.Assert(t, auth1.Equal(*auth2))
	})

	t.Run("different IDs", func(t *testing.T) {
		sessionVars := map[string]goenvconf.EnvAny{
			"x-hasura-role": goenvconf.NewEnvAnyValue("admin"),
		}

		config1 := &RelyAuthNoAuthConfig{
			ID:               "test-id-1",
			Mode:             authmode.AuthModeNoAuth,
			SessionVariables: sessionVars,
		}

		config2 := &RelyAuthNoAuthConfig{
			ID:               "test-id-2",
			Mode:             authmode.AuthModeNoAuth,
			SessionVariables: sessionVars,
		}

		auth1, err := NewNoAuth(context.TODO(), config1, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)

		auth2, err := NewNoAuth(context.TODO(), config2, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)

		assert.Assert(t, !auth1.Equal(*auth2))
	})

	t.Run("different session variables", func(t *testing.T) {
		config1 := &RelyAuthNoAuthConfig{
			ID:   "test-id",
			Mode: authmode.AuthModeNoAuth,
			SessionVariables: map[string]goenvconf.EnvAny{
				"x-hasura-role": goenvconf.NewEnvAnyValue("admin"),
			},
		}

		config2 := &RelyAuthNoAuthConfig{
			ID:   "test-id",
			Mode: authmode.AuthModeNoAuth,
			SessionVariables: map[string]goenvconf.EnvAny{
				"x-hasura-role": goenvconf.NewEnvAnyValue("user"),
			},
		}

		auth1, err := NewNoAuth(context.TODO(), config1, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)

		auth2, err := NewNoAuth(context.TODO(), config2, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)

		assert.Assert(t, !auth1.Equal(*auth2))
	})
}

func TestRelyAuthNoAuthConfig_IsZero(t *testing.T) {
	t.Run("zero config", func(t *testing.T) {
		config := RelyAuthNoAuthConfig{}
		assert.Assert(t, config.IsZero())
	})

	t.Run("non-zero with ID", func(t *testing.T) {
		config := RelyAuthNoAuthConfig{
			ID: "test-id",
		}
		assert.Assert(t, !config.IsZero())
	})

	t.Run("non-zero with mode", func(t *testing.T) {
		config := RelyAuthNoAuthConfig{
			Mode: authmode.AuthModeNoAuth,
		}
		assert.Assert(t, !config.IsZero())
	})

	t.Run("non-zero with session variables", func(t *testing.T) {
		config := RelyAuthNoAuthConfig{
			SessionVariables: map[string]goenvconf.EnvAny{
				"x-hasura-role": goenvconf.NewEnvAnyValue("admin"),
			},
		}
		assert.Assert(t, !config.IsZero())
	})
}

func TestRelyAuthNoAuthConfig_Equal(t *testing.T) {
	t.Run("equal configs", func(t *testing.T) {
		sessionVars := map[string]goenvconf.EnvAny{
			"x-hasura-role": goenvconf.NewEnvAnyValue("admin"),
		}

		config1 := RelyAuthNoAuthConfig{
			ID:               "test-id",
			Mode:             authmode.AuthModeNoAuth,
			SessionVariables: sessionVars,
		}

		config2 := RelyAuthNoAuthConfig{
			ID:               "test-id",
			Mode:             authmode.AuthModeNoAuth,
			SessionVariables: sessionVars,
		}

		assert.Assert(t, config1.Equal(config2))
	})

	t.Run("different IDs", func(t *testing.T) {
		config1 := RelyAuthNoAuthConfig{
			ID:   "test-id-1",
			Mode: authmode.AuthModeNoAuth,
		}

		config2 := RelyAuthNoAuthConfig{
			ID:   "test-id-2",
			Mode: authmode.AuthModeNoAuth,
		}

		assert.Assert(t, !config1.Equal(config2))
	})

	t.Run("different modes", func(t *testing.T) {
		config1 := RelyAuthNoAuthConfig{
			ID:   "test-id",
			Mode: authmode.AuthModeNoAuth,
		}

		config2 := RelyAuthNoAuthConfig{
			ID:   "test-id",
			Mode: authmode.AuthModeAPIKey,
		}

		assert.Assert(t, !config1.Equal(config2))
	})

	t.Run("different session variables", func(t *testing.T) {
		config1 := RelyAuthNoAuthConfig{
			ID:   "test-id",
			Mode: authmode.AuthModeNoAuth,
			SessionVariables: map[string]goenvconf.EnvAny{
				"x-hasura-role": goenvconf.NewEnvAnyValue("admin"),
			},
		}

		config2 := RelyAuthNoAuthConfig{
			ID:   "test-id",
			Mode: authmode.AuthModeNoAuth,
			SessionVariables: map[string]goenvconf.EnvAny{
				"x-hasura-role": goenvconf.NewEnvAnyValue("user"),
			},
		}

		assert.Assert(t, !config1.Equal(config2))
	})
}

func TestNewNoAuth_WithEnvironmentVariables(t *testing.T) {
	// EnvAny expects JSON-encoded values in environment variables
	t.Setenv("TEST_ROLE", `"env-admin"`)
	t.Setenv("TEST_USER_ID", `"12345"`)

	sessionVariables := map[string]goenvconf.EnvAny{
		"x-hasura-role":    goenvconf.NewEnvAnyVariable("TEST_ROLE"),
		"x-hasura-user-id": goenvconf.NewEnvAnyVariable("TEST_USER_ID"),
	}

	config := &RelyAuthNoAuthConfig{
		ID:               "test-env",
		Mode:             authmode.AuthModeNoAuth,
		SessionVariables: sessionVariables,
	}

	authenticator, err := NewNoAuth(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)

	result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{})
	assert.NilError(t, err)
	assert.Equal(t, "test-env", result.ID)
	assert.DeepEqual(t, map[string]any{
		"x-hasura-role":    "env-admin",
		"x-hasura-user-id": "12345",
	}, result.SessionVariables)
}

func TestNewNoAuth_EmptySessionVariables(t *testing.T) {
	config := &RelyAuthNoAuthConfig{
		ID:               "test-empty",
		Mode:             authmode.AuthModeNoAuth,
		SessionVariables: map[string]goenvconf.EnvAny{},
	}

	authenticator, err := NewNoAuth(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)

	result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{})
	assert.NilError(t, err)
	assert.Equal(t, "test-empty", result.ID)
	assert.DeepEqual(t, map[string]any{}, result.SessionVariables)
}

func TestNewNoAuth_ComplexSessionVariables(t *testing.T) {
	sessionVariables := map[string]goenvconf.EnvAny{
		"x-hasura-role":          goenvconf.NewEnvAnyValue("admin"),
		"x-hasura-user-id":       goenvconf.NewEnvAnyValue("user-123"),
		"x-hasura-allowed-roles": goenvconf.NewEnvAnyValue([]string{"admin", "user", "guest"}),
		"x-hasura-org-id":        goenvconf.NewEnvAnyValue(42),
		"x-hasura-is-active":     goenvconf.NewEnvAnyValue(true),
		"x-hasura-metadata": goenvconf.NewEnvAnyValue(map[string]any{
			"department": "engineering",
			"level":      5,
		}),
	}

	config := &RelyAuthNoAuthConfig{
		ID:               "test-complex",
		Mode:             authmode.AuthModeNoAuth,
		SessionVariables: sessionVariables,
	}

	authenticator, err := NewNoAuth(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)

	result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{})
	assert.NilError(t, err)
	assert.Equal(t, "test-complex", result.ID)
	assert.Equal(t, "admin", result.SessionVariables["x-hasura-role"])
	assert.Equal(t, "user-123", result.SessionVariables["x-hasura-user-id"])
	assert.DeepEqual(t, []string{"admin", "user", "guest"}, result.SessionVariables["x-hasura-allowed-roles"])
	assert.Equal(t, 42, result.SessionVariables["x-hasura-org-id"])
	assert.Equal(t, true, result.SessionVariables["x-hasura-is-active"])
	assert.DeepEqual(t, map[string]any{
		"department": "engineering",
		"level":      5,
	}, result.SessionVariables["x-hasura-metadata"])
}

func TestNewNoAuth_WithoutID(t *testing.T) {
	config := &RelyAuthNoAuthConfig{
		Mode: authmode.AuthModeNoAuth,
		SessionVariables: map[string]goenvconf.EnvAny{
			"x-hasura-role": goenvconf.NewEnvAnyValue("guest"),
		},
	}

	authenticator, err := NewNoAuth(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)

	result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{})
	assert.NilError(t, err)
	assert.Equal(t, "", result.ID)
	assert.DeepEqual(t, map[string]any{
		"x-hasura-role": "guest",
	}, result.SessionVariables)
}

func TestNoAuth_AuthenticateWithDifferentRequestData(t *testing.T) {
	config := &RelyAuthNoAuthConfig{
		ID:   "test-request",
		Mode: authmode.AuthModeNoAuth,
		SessionVariables: map[string]goenvconf.EnvAny{
			"x-hasura-role": goenvconf.NewEnvAnyValue("public"),
		},
	}

	authenticator, err := NewNoAuth(context.TODO(), config, authmode.RelyAuthenticatorOptions{})
	assert.NilError(t, err)

	t.Run("with headers", func(t *testing.T) {
		result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
			Headers: map[string]string{
				"Authorization": "Bearer token",
				"X-Custom":      "value",
			},
		})
		assert.NilError(t, err)
		assert.Equal(t, "test-request", result.ID)
		assert.DeepEqual(t, map[string]any{
			"x-hasura-role": "public",
		}, result.SessionVariables)
	})

	t.Run("with URL", func(t *testing.T) {
		result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
			URL: "/api/data?token=xyz789",
			Headers: map[string]string{
				"Cookie": "session=abc123",
			},
		})
		assert.NilError(t, err)
		assert.Equal(t, "test-request", result.ID)
		assert.DeepEqual(t, map[string]any{
			"x-hasura-role": "public",
		}, result.SessionVariables)
	})

	t.Run("with request body", func(t *testing.T) {
		result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Request: []byte(`{"query": "{ users { id } }"}`),
		})
		assert.NilError(t, err)
		assert.Equal(t, "test-request", result.ID)
		assert.DeepEqual(t, map[string]any{
			"x-hasura-role": "public",
		}, result.SessionVariables)
	})
}
