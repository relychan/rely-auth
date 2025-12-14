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
	result, err := authenticator.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{},
	})
	assert.NilError(t, err)
	assert.Equal(t, "test-noauth", result.ID)
	assert.DeepEqual(t, map[string]any{
		"x-hasura-role":          "anonymous",
		"x-hasura-allowed-roles": []string{"anonymous"},
	}, result.SessionVariables)
}

func TestNoAuth_Reload(t *testing.T) {
	config := &RelyAuthNoAuthConfig{
		Mode: authmode.AuthModeNoAuth,
		SessionVariables: map[string]goenvconf.EnvAny{
			"x-hasura-role": goenvconf.NewEnvAnyValue("guest"),
		},
	}

	authenticator, err := NewNoAuth(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)

	// Test reload
	err = authenticator.Reload(context.Background())
	assert.NilError(t, err)

	// Verify session variables are still correct after reload
	result, err := authenticator.Authenticate(context.Background(), authmode.AuthenticateRequestData{})
	assert.NilError(t, err)
	assert.DeepEqual(t, map[string]any{
		"x-hasura-role": "guest",
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

func TestNoAuth_ConcurrentAccess(t *testing.T) {
	config := &RelyAuthNoAuthConfig{
		Mode: authmode.AuthModeNoAuth,
		SessionVariables: map[string]goenvconf.EnvAny{
			"x-hasura-role": goenvconf.NewEnvAnyValue("user"),
		},
	}

	authenticator, err := NewNoAuth(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)

	// Test concurrent authentication and reload
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := authenticator.Authenticate(context.Background(), authmode.AuthenticateRequestData{})
			assert.NilError(t, err)
			done <- true
		}()
	}

	for i := 0; i < 5; i++ {
		go func() {
			err := authenticator.Reload(context.Background())
			assert.NilError(t, err)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 15; i++ {
		<-done
	}
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
