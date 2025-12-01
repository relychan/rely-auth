package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hasura/goenvconf"
	"github.com/relychan/gohttpc"
	"github.com/relychan/rely-auth/auth/authmode"
	"gotest.tools/v3/assert"
)

func TestWebhookAuthenticator_Authenticate_Success(t *testing.T) {
	// Create a mock webhook server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"x-hasura-role":    "user",
			"x-hasura-user-id": "123",
		})
	}))
	defer server.Close()

	config := RelyAuthWebhookConfig{
		ID:     "test-webhook",
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
		CustomRequest: &WebhookAuthCustomRequestConfig{
			Headers: &WebhookAuthHeadersConfig{},
		},
	}

	httpClient := gohttpc.NewClient()
	authenticator, err := NewWebhookAuthenticator(config, httpClient)
	assert.NilError(t, err)
	defer authenticator.Close()

	result, err := authenticator.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"authorization": "Bearer token123",
		},
	})
	assert.NilError(t, err)
	assert.Equal(t, "test-webhook", result.ID)
	assert.DeepEqual(t, map[string]any{
		"x-hasura-role":    "user",
		"x-hasura-user-id": "123",
	}, result.SessionVariables)
}

func TestWebhookAuthenticator_Authenticate_Unauthorized(t *testing.T) {
	// Create a mock webhook server that returns 401
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
	}))
	defer server.Close()

	config := RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
		CustomRequest: &WebhookAuthCustomRequestConfig{
			Headers: &WebhookAuthHeadersConfig{},
		},
	}

	httpClient := gohttpc.NewClient()
	authenticator, err := NewWebhookAuthenticator(config, httpClient)
	assert.NilError(t, err)
	defer authenticator.Close()

	_, err = authenticator.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"authorization": "Bearer invalid",
		},
	})
	assert.Assert(t, err != nil)
}

func TestWebhookAuthenticator_Authenticate_EmptyBody(t *testing.T) {
	// Create a mock webhook server that returns empty body
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
		CustomRequest: &WebhookAuthCustomRequestConfig{
			Headers: &WebhookAuthHeadersConfig{},
		},
	}

	httpClient := gohttpc.NewClient()
	authenticator, err := NewWebhookAuthenticator(config, httpClient)
	assert.NilError(t, err)
	defer authenticator.Close()

	_, err = authenticator.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{},
	})
	assert.ErrorContains(t, err, ErrResponseBodyRequired.Error())
}

func TestWebhookAuthenticator_Mode(t *testing.T) {
	config := RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue("http://example.com"),
		Method: http.MethodGet,
		CustomRequest: &WebhookAuthCustomRequestConfig{
			Headers: &WebhookAuthHeadersConfig{},
		},
	}

	httpClient := gohttpc.NewClient()
	authenticator, err := NewWebhookAuthenticator(config, httpClient)
	assert.NilError(t, err)
	defer authenticator.Close()

	assert.Equal(t, authmode.AuthModeWebhook, authenticator.Mode())
}

func TestWebhookAuthenticator_Reload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"x-hasura-role": "user",
		})
	}))
	defer server.Close()

	config := RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
		CustomRequest: &WebhookAuthCustomRequestConfig{
			Headers: &WebhookAuthHeadersConfig{},
		},
	}

	httpClient := gohttpc.NewClient()
	authenticator, err := NewWebhookAuthenticator(config, httpClient)
	assert.NilError(t, err)
	defer authenticator.Close()

	err = authenticator.Reload(context.Background())
	assert.NilError(t, err)
}

func TestWebhookAuthenticator_GET_Method(t *testing.T) {
	// Create a mock webhook server for GET requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"x-hasura-role": "guest",
		})
	}))
	defer server.Close()

	config := RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
	}

	httpClient := gohttpc.NewClient()
	authenticator, err := NewWebhookAuthenticator(config, httpClient)
	assert.NilError(t, err)
	defer authenticator.Close()

	result, err := authenticator.Authenticate(context.Background(), authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"authorization": "Bearer token",
		},
	})
	assert.NilError(t, err)
	assert.DeepEqual(t, map[string]any{
		"x-hasura-role": "guest",
	}, result.SessionVariables)
}

func TestWebhookConfig_Validate(t *testing.T) {
	testCases := []struct {
		Name        string
		Config      RelyAuthWebhookConfig
		ExpectError string
	}{
		{
			Name: "valid_post",
			Config: RelyAuthWebhookConfig{
				Mode:   authmode.AuthModeWebhook,
				URL:    goenvconf.NewEnvStringValue("http://example.com"),
				Method: http.MethodPost,
			},
			ExpectError: "",
		},
		{
			Name: "valid_get",
			Config: RelyAuthWebhookConfig{
				Mode:   authmode.AuthModeWebhook,
				URL:    goenvconf.NewEnvStringValue("http://example.com"),
				Method: http.MethodGet,
			},
			ExpectError: "",
		},
		{
			Name: "missing_url",
			Config: RelyAuthWebhookConfig{
				Mode:   authmode.AuthModeWebhook,
				Method: http.MethodPost,
			},
			ExpectError: "required field",
		},
		{
			Name: "invalid_method",
			Config: RelyAuthWebhookConfig{
				Mode:   authmode.AuthModeWebhook,
				URL:    goenvconf.NewEnvStringValue("http://example.com"),
				Method: http.MethodPut,
			},
			ExpectError: ErrMethodNotAllowed.Error(),
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

func TestWebhookConfig_GetMode(t *testing.T) {
	config := RelyAuthWebhookConfig{}
	assert.Equal(t, authmode.AuthModeWebhook, config.GetMode())
}

func TestNewRelyAuthWebhookConfig(t *testing.T) {
	url := goenvconf.NewEnvStringValue("http://example.com")
	config := NewRelyAuthWebhookConfig(url, http.MethodPost)

	assert.Assert(t, config != nil)
	assert.Equal(t, authmode.AuthModeWebhook, config.Mode)
	assert.Equal(t, http.MethodPost, config.Method)
	assert.DeepEqual(t, url, config.URL)
}
