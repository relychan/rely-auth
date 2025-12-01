package apikey

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/hasura/goenvconf"
	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/rely-auth/auth/authmode"
	"gotest.tools/v3/assert"
)

func TestAPIKeyAuthenticator(t *testing.T) {
	apiKey := rand.Text()
	sessionVariables := map[string]goenvconf.EnvAny{
		"foo": goenvconf.NewEnvAnyValue("bar"),
	}

	t.Setenv("API_KEY", apiKey)

	config := NewRelyAuthAPIKeyConfig(authscheme.TokenLocation{
		In:     authscheme.InHeader,
		Name:   "Authorization",
		Scheme: "bearer",
	}, goenvconf.NewEnvStringVariable("API_KEY"), sessionVariables)

	authenticator, err := NewAPIKeyAuthenticator(*config)
	assert.NilError(t, err)

	for range 10 {
		go func() {
			result, err := authenticator.Authenticate(context.Background(), authmode.AuthenticateRequestData{
				Headers: map[string]string{
					"authorization": "Bearer " + apiKey,
				},
			})
			assert.NilError(t, err)
			assert.DeepEqual(t, result.SessionVariables, map[string]any{"foo": "bar"})
			time.Sleep(time.Millisecond)
		}()
	}

	for range 10 {
		assert.NilError(t, authenticator.Reload(context.Background()))
		time.Sleep(time.Millisecond)
	}
}

func TestAPIKeyAuthenticator_Unauthorized(t *testing.T) {
	apiKey := "correct-key"
	t.Setenv("API_KEY", apiKey)

	config := NewRelyAuthAPIKeyConfig(authscheme.TokenLocation{
		In:     authscheme.InHeader,
		Name:   "Authorization",
		Scheme: "bearer",
	}, goenvconf.NewEnvStringVariable("API_KEY"), map[string]goenvconf.EnvAny{})

	authenticator, err := NewAPIKeyAuthenticator(*config)
	assert.NilError(t, err)

	// Test with wrong key
	_, err = authenticator.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"authorization": "Bearer wrong-key",
		},
	})
	assert.ErrorContains(t, err, "Unauthorized")

	// Test with missing header
	_, err = authenticator.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{},
	})
	assert.ErrorContains(t, err, authmode.ErrAuthTokenNotFound.Error())
}

func TestAPIKeyAuthenticator_Mode(t *testing.T) {
	t.Setenv("API_KEY", "test")

	config := NewRelyAuthAPIKeyConfig(authscheme.TokenLocation{
		In:   authscheme.InHeader,
		Name: "X-API-Key",
	}, goenvconf.NewEnvStringVariable("API_KEY"), map[string]goenvconf.EnvAny{})

	authenticator, err := NewAPIKeyAuthenticator(*config)
	assert.NilError(t, err)

	assert.Equal(t, authmode.AuthModeAPIKey, authenticator.Mode())
}

func TestAPIKeyAuthenticator_Close(t *testing.T) {
	t.Setenv("API_KEY", "test")

	config := NewRelyAuthAPIKeyConfig(authscheme.TokenLocation{
		In:   authscheme.InHeader,
		Name: "X-API-Key",
	}, goenvconf.NewEnvStringVariable("API_KEY"), map[string]goenvconf.EnvAny{})

	authenticator, err := NewAPIKeyAuthenticator(*config)
	assert.NilError(t, err)

	err = authenticator.Close()
	assert.NilError(t, err)
}

func TestAPIKeyConfig_Validate(t *testing.T) {
	testCases := []struct {
		Name        string
		Config      RelyAuthAPIKeyConfig
		ExpectError string
	}{
		{
			Name: "valid_config",
			Config: RelyAuthAPIKeyConfig{
				Mode: authmode.AuthModeAPIKey,
				TokenLocation: authscheme.TokenLocation{
					In:   authscheme.InHeader,
					Name: "Authorization",
				},
				Value: goenvconf.NewEnvStringValue("secret"),
			},
			ExpectError: "",
		},
		{
			Name: "missing_name",
			Config: RelyAuthAPIKeyConfig{
				Mode: authmode.AuthModeAPIKey,
				TokenLocation: authscheme.TokenLocation{
					In: authscheme.InHeader,
				},
				Value: goenvconf.NewEnvStringValue("secret"),
			},
			ExpectError: "required field",
		},
		{
			Name: "missing_value",
			Config: RelyAuthAPIKeyConfig{
				Mode: authmode.AuthModeAPIKey,
				TokenLocation: authscheme.TokenLocation{
					In:   authscheme.InHeader,
					Name: "Authorization",
				},
			},
			ExpectError: "required field",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			err := tc.Config.Validate()
			if tc.ExpectError != "" {
				assert.ErrorContains(t, err, tc.ExpectError)
			} else {
				assert.NilError(t, err)
			}
		})
	}
}

func TestAPIKeyConfig_GetMode(t *testing.T) {
	config := RelyAuthAPIKeyConfig{}
	assert.Equal(t, authmode.AuthModeAPIKey, config.GetMode())
}
