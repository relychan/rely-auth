package auth

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/hasura/goenvconf"
	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/rely-auth/auth/apikey"
	"github.com/relychan/rely-auth/auth/authmode"
	"github.com/relychan/rely-auth/auth/noauth"
	"gotest.tools/v3/assert"
)

func TestNewRelyAuthManager(t *testing.T) {
	config := &RelyAuthConfig{
		Definitions: []RelyAuthDefinition{
			NewRelyAuthDefinition(&noauth.RelyAuthNoAuthConfig{
				Mode: authmode.AuthModeNoAuth,
				SessionVariables: map[string]goenvconf.EnvAny{
					"x-hasura-role": goenvconf.NewEnvAnyValue("anonymous"),
				},
			}),
		},
	}

	manager, err := NewRelyAuthManager(context.TODO(), config)
	assert.NilError(t, err)
	assert.Assert(t, manager != nil)

	err = manager.Close()
	assert.NilError(t, err)
}

func TestRelyAuthManager_Authenticate_NoAuth(t *testing.T) {
	config := &RelyAuthConfig{
		Definitions: []RelyAuthDefinition{
			{
				RelyAuthDefinitionInterface: &noauth.RelyAuthNoAuthConfig{
					Mode: authmode.AuthModeNoAuth,
					SessionVariables: map[string]goenvconf.EnvAny{
						"x-hasura-role": goenvconf.NewEnvAnyValue("guest"),
					},
				},
			},
		},
	}

	manager, err := NewRelyAuthManager(context.TODO(), config)
	assert.NilError(t, err)
	defer manager.Close()

	result, err := manager.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{},
	})
	assert.NilError(t, err)
	assert.DeepEqual(t, map[string]any{
		"x-hasura-role": "guest",
	}, result)
}

func TestRelyAuthManager_Authenticate_APIKey(t *testing.T) {
	apiKey := "test-secret-key"
	t.Setenv("TEST_API_KEY", apiKey)

	config := &RelyAuthConfig{
		Definitions: []RelyAuthDefinition{
			{
				RelyAuthDefinitionInterface: &apikey.RelyAuthAPIKeyConfig{
					Mode: authmode.AuthModeAPIKey,
					TokenLocation: authscheme.TokenLocation{
						In:   authscheme.InHeader,
						Name: "Authorization",
					},
					Value: goenvconf.NewEnvStringVariable("TEST_API_KEY"),
					SessionVariables: map[string]goenvconf.EnvAny{
						"x-hasura-role": goenvconf.NewEnvAnyValue("admin"),
					},
				},
			},
		},
	}

	manager, err := NewRelyAuthManager(context.TODO(), config)
	assert.NilError(t, err)
	defer manager.Close()

	// Test successful authentication
	result, err := manager.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"authorization": apiKey,
		},
	})
	assert.NilError(t, err)
	assert.DeepEqual(t, map[string]any{
		"x-hasura-role": "admin",
	}, result)

	// Test failed authentication
	_, err = manager.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"authorization": "wrong-key",
		},
	})
	assert.ErrorContains(t, err, "Unauthorized")
}

func TestRelyAuthManager_Authenticate_Fallback(t *testing.T) {
	apiKey := "correct-key"
	t.Setenv("FALLBACK_API_KEY", apiKey)

	config := &RelyAuthConfig{
		Definitions: []RelyAuthDefinition{
			{
				RelyAuthDefinitionInterface: &apikey.RelyAuthAPIKeyConfig{
					Mode: authmode.AuthModeAPIKey,
					TokenLocation: authscheme.TokenLocation{
						In:   authscheme.InHeader,
						Name: "Authorization",
					},
					Value: goenvconf.NewEnvStringVariable("FALLBACK_API_KEY"),
					SessionVariables: map[string]goenvconf.EnvAny{
						"x-hasura-role": goenvconf.NewEnvAnyValue("user"),
					},
				},
			},
			{
				RelyAuthDefinitionInterface: &noauth.RelyAuthNoAuthConfig{
					Mode: authmode.AuthModeNoAuth,
					SessionVariables: map[string]goenvconf.EnvAny{
						"x-hasura-role": goenvconf.NewEnvAnyValue("anonymous"),
					},
				},
			},
		},
	}

	manager, err := NewRelyAuthManager(context.TODO(), config)
	assert.NilError(t, err)
	defer manager.Close()

	// Test fallback to noAuth when no token provided
	result, err := manager.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{},
	})
	assert.NilError(t, err)
	assert.DeepEqual(t, map[string]any{
		"x-hasura-role": "anonymous",
	}, result)
}

func TestRelyAuthManager_Authenticate_StrictMode(t *testing.T) {
	apiKey := "strict-key"
	t.Setenv("STRICT_API_KEY", apiKey)

	config := &RelyAuthConfig{
		Settings: &authmode.RelyAuthSettings{
			Strict: true,
		},
		Definitions: []RelyAuthDefinition{
			{
				RelyAuthDefinitionInterface: &apikey.RelyAuthAPIKeyConfig{
					Mode: authmode.AuthModeAPIKey,
					TokenLocation: authscheme.TokenLocation{
						In:   authscheme.InHeader,
						Name: "Authorization",
					},
					Value: goenvconf.NewEnvStringVariable("STRICT_API_KEY"),
					SessionVariables: map[string]goenvconf.EnvAny{
						"x-hasura-role": goenvconf.NewEnvAnyValue("user"),
					},
				},
			},
			{
				RelyAuthDefinitionInterface: &noauth.RelyAuthNoAuthConfig{
					Mode: authmode.AuthModeNoAuth,
					SessionVariables: map[string]goenvconf.EnvAny{
						"x-hasura-role": goenvconf.NewEnvAnyValue("anonymous"),
					},
				},
			},
		},
	}

	manager, err := NewRelyAuthManager(context.TODO(), config)
	assert.NilError(t, err)
	defer manager.Close()

	// Test strict mode: should not fallback to noAuth when wrong token provided
	_, err = manager.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"authorization": "wrong-key",
		},
	})
	assert.ErrorContains(t, err, "Unauthorized")
}

func TestRelyAuthManager_Reload(t *testing.T) {
	config := &RelyAuthConfig{
		Definitions: []RelyAuthDefinition{
			{
				RelyAuthDefinitionInterface: &noauth.RelyAuthNoAuthConfig{
					Mode: authmode.AuthModeNoAuth,
					SessionVariables: map[string]goenvconf.EnvAny{
						"x-hasura-role": goenvconf.NewEnvAnyValue("guest"),
					},
				},
			},
		},
	}

	manager, err := NewRelyAuthManager(context.TODO(), config)
	assert.NilError(t, err)
	defer manager.Close()

	err = manager.Reload(context.Background())
	assert.NilError(t, err)
}

func TestRelyAuthManager_WithOptions(t *testing.T) {
	config := &RelyAuthConfig{
		Definitions: []RelyAuthDefinition{
			{
				RelyAuthDefinitionInterface: &noauth.RelyAuthNoAuthConfig{
					Mode:             authmode.AuthModeNoAuth,
					SessionVariables: map[string]goenvconf.EnvAny{},
				},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	manager, err := NewRelyAuthManager(context.TODO(), config, authmode.WithLogger(logger))
	assert.NilError(t, err)
	assert.Assert(t, manager != nil)

	err = manager.Close()
	assert.NilError(t, err)
}

func TestRelyAuthManager_MultipleAuthenticators(t *testing.T) {
	apiKey1 := "key1"
	apiKey2 := "key2"
	t.Setenv("API_KEY_1", apiKey1)
	t.Setenv("API_KEY_2", apiKey2)

	config := &RelyAuthConfig{
		Definitions: []RelyAuthDefinition{
			{
				RelyAuthDefinitionInterface: &apikey.RelyAuthAPIKeyConfig{
					ID:   "auth1",
					Mode: authmode.AuthModeAPIKey,
					TokenLocation: authscheme.TokenLocation{
						In:   authscheme.InHeader,
						Name: "X-API-Key-1",
					},
					Value: goenvconf.NewEnvStringVariable("API_KEY_1"),
					SessionVariables: map[string]goenvconf.EnvAny{
						"x-hasura-role": goenvconf.NewEnvAnyValue("service1"),
					},
				},
			},
			{
				RelyAuthDefinitionInterface: &apikey.RelyAuthAPIKeyConfig{
					ID:   "auth2",
					Mode: authmode.AuthModeAPIKey,
					TokenLocation: authscheme.TokenLocation{
						In:   authscheme.InHeader,
						Name: "X-API-Key-2",
					},
					Value: goenvconf.NewEnvStringVariable("API_KEY_2"),
					SessionVariables: map[string]goenvconf.EnvAny{
						"x-hasura-role": goenvconf.NewEnvAnyValue("service2"),
					},
				},
			},
		},
	}

	manager, err := NewRelyAuthManager(context.TODO(), config)
	assert.NilError(t, err)
	defer manager.Close()

	// Test first authenticator
	result, err := manager.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"x-api-key-1": apiKey1,
		},
	})
	assert.NilError(t, err)
	assert.DeepEqual(t, map[string]any{
		"x-hasura-role": "service1",
	}, result)

	// Test second authenticator
	result, err = manager.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"x-api-key-2": apiKey2,
		},
	})
	assert.NilError(t, err)
	assert.DeepEqual(t, map[string]any{
		"x-hasura-role": "service2",
	}, result)
}

func TestRelyAuthManager_RefreshProcess(t *testing.T) {
	manager, err := NewRelyAuthManager(context.TODO(), &RelyAuthConfig{})
	assert.NilError(t, err)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	manager.startReloadProcess(ctx, 1)
}
