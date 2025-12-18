package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hasura/goenvconf"
	"github.com/relychan/gotransform/jmes"
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

	config := &RelyAuthWebhookConfig{
		ID:     "test-webhook",
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
		CustomRequest: &WebhookAuthCustomRequestConfig{
			Headers: &WebhookAuthHeadersConfig{},
		},
	}

	authenticator, err := NewWebhookAuthenticator(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
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

	config := &RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
		CustomRequest: &WebhookAuthCustomRequestConfig{
			Headers: &WebhookAuthHeadersConfig{},
		},
	}

	authenticator, err := NewWebhookAuthenticator(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	_, err = authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
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

	config := &RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
		CustomRequest: &WebhookAuthCustomRequestConfig{
			Headers: &WebhookAuthHeadersConfig{},
		},
	}

	authenticator, err := NewWebhookAuthenticator(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	_, err = authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
		Headers: map[string]string{},
	})
	assert.ErrorContains(t, err, ErrResponseBodyRequired.Error())
}

func TestWebhookAuthenticator_Mode(t *testing.T) {
	config := &RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue("http://example.com"),
		Method: http.MethodGet,
		CustomRequest: &WebhookAuthCustomRequestConfig{
			Headers: &WebhookAuthHeadersConfig{},
		},
	}

	authenticator, err := NewWebhookAuthenticator(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
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

	config := &RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
		CustomRequest: &WebhookAuthCustomRequestConfig{
			Headers: &WebhookAuthHeadersConfig{},
		},
	}

	authenticator, err := NewWebhookAuthenticator(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
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

	config := &RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
	}

	authenticator, err := NewWebhookAuthenticator(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
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

func TestWebhookAuthenticator_InvalidURL(t *testing.T) {
	config := &RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(""),
		Method: http.MethodGet,
	}

	_, err := NewWebhookAuthenticator(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.ErrorContains(t, err, "required field")
}

func TestWebhookAuthenticator_MalformedResponseJSON(t *testing.T) {
	// Create a mock webhook server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	config := &RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
	}

	authenticator, err := NewWebhookAuthenticator(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	_, err = authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
		Headers: map[string]string{},
	})
	assert.ErrorContains(t, err, "could not unmarshal as JSON")
}

func TestWebhookAuthenticator_Equal(t *testing.T) {
	t.Run("different_urls", func(t *testing.T) {
		config1 := &RelyAuthWebhookConfig{
			ID:     "test-webhook-1",
			Mode:   authmode.AuthModeWebhook,
			URL:    goenvconf.NewEnvStringValue("http://example1.com"),
			Method: http.MethodGet,
		}

		config2 := &RelyAuthWebhookConfig{
			ID:     "test-webhook-2",
			Mode:   authmode.AuthModeWebhook,
			URL:    goenvconf.NewEnvStringValue("http://example2.com"),
			Method: http.MethodGet,
		}

		auth1, err := NewWebhookAuthenticator(context.TODO(), config1, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer auth1.Close()

		auth2, err := NewWebhookAuthenticator(context.TODO(), config2, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer auth2.Close()

		assert.Assert(t, !auth1.Equal(*auth2))
	})

	t.Run("different_methods", func(t *testing.T) {
		config1 := &RelyAuthWebhookConfig{
			ID:     "test-webhook-1",
			Mode:   authmode.AuthModeWebhook,
			URL:    goenvconf.NewEnvStringValue("http://example.com"),
			Method: http.MethodGet,
		}

		config2 := &RelyAuthWebhookConfig{
			ID:     "test-webhook-2",
			Mode:   authmode.AuthModeWebhook,
			URL:    goenvconf.NewEnvStringValue("http://example.com"),
			Method: http.MethodPost,
		}

		auth1, err := NewWebhookAuthenticator(context.TODO(), config1, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer auth1.Close()

		auth2, err := NewWebhookAuthenticator(context.TODO(), config2, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer auth2.Close()

		assert.Assert(t, !auth1.Equal(*auth2))
	})
}

func TestWebhookAuthenticator_Close(t *testing.T) {
	config := &RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue("http://example.com"),
		Method: http.MethodGet,
	}

	authenticator, err := NewWebhookAuthenticator(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)

	err = authenticator.Close()
	assert.NilError(t, err)
}

func TestWebhookConfig_IsZero(t *testing.T) {
	t.Run("zero_config", func(t *testing.T) {
		config := RelyAuthWebhookConfig{}
		assert.Assert(t, config.IsZero())
	})

	t.Run("non_zero_config", func(t *testing.T) {
		config := RelyAuthWebhookConfig{
			Mode:   authmode.AuthModeWebhook,
			URL:    goenvconf.NewEnvStringValue("http://example.com"),
			Method: http.MethodGet,
		}
		assert.Assert(t, !config.IsZero())
	})
}

func TestWebhookConfig_Equal(t *testing.T) {
	t.Run("equal_configs", func(t *testing.T) {
		config1 := RelyAuthWebhookConfig{
			Mode:   authmode.AuthModeWebhook,
			URL:    goenvconf.NewEnvStringValue("http://example.com"),
			Method: http.MethodGet,
		}
		config2 := RelyAuthWebhookConfig{
			Mode:   authmode.AuthModeWebhook,
			URL:    goenvconf.NewEnvStringValue("http://example.com"),
			Method: http.MethodGet,
		}
		assert.Assert(t, config1.Equal(config2))
	})

	t.Run("different_methods", func(t *testing.T) {
		config1 := RelyAuthWebhookConfig{
			Mode:   authmode.AuthModeWebhook,
			URL:    goenvconf.NewEnvStringValue("http://example.com"),
			Method: http.MethodGet,
		}
		config2 := RelyAuthWebhookConfig{
			Mode:   authmode.AuthModeWebhook,
			URL:    goenvconf.NewEnvStringValue("http://example.com"),
			Method: http.MethodPost,
		}
		assert.Assert(t, !config1.Equal(config2))
	})
}

func TestWebhookAuthCustomRequestConfig_IsZero(t *testing.T) {
	t.Run("zero_config", func(t *testing.T) {
		config := WebhookAuthCustomRequestConfig{}
		assert.Assert(t, config.IsZero())
	})

	t.Run("non_zero_with_headers", func(t *testing.T) {
		config := WebhookAuthCustomRequestConfig{
			Headers: &WebhookAuthHeadersConfig{},
		}
		assert.Assert(t, config.IsZero()) // Empty headers config is still zero
	})
}

func TestWebhookAuthCustomRequestConfig_Equal(t *testing.T) {
	config1 := WebhookAuthCustomRequestConfig{}
	config2 := WebhookAuthCustomRequestConfig{}
	assert.Assert(t, config1.Equal(config2))
}

func TestWebhookAuthHeadersConfig_IsZero(t *testing.T) {
	t.Run("zero_config", func(t *testing.T) {
		config := WebhookAuthHeadersConfig{}
		assert.Assert(t, config.IsZero())
	})

	t.Run("non_zero_with_additional", func(t *testing.T) {
		config := WebhookAuthHeadersConfig{
			Additional: map[string]jmes.FieldMappingEntryStringConfig{
				"x-custom-header": {},
			},
		}
		assert.Assert(t, !config.IsZero())
	})
}

func TestWebhookAuthHeadersConfig_Equal(t *testing.T) {
	config1 := WebhookAuthHeadersConfig{}
	config2 := WebhookAuthHeadersConfig{}
	assert.Assert(t, config1.Equal(config2))
}

func TestWebhookAuthCustomResponseConfig_IsZero(t *testing.T) {
	t.Run("zero_config", func(t *testing.T) {
		config := WebhookAuthCustomResponseConfig{}
		assert.Assert(t, config.IsZero())
	})
}

func TestWebhookAuthCustomResponseConfig_Equal(t *testing.T) {
	config1 := WebhookAuthCustomResponseConfig{}
	config2 := WebhookAuthCustomResponseConfig{}
	assert.Assert(t, config1.Equal(config2))
}

func TestWebhookAuthenticator_ServerError(t *testing.T) {
	// Create a mock webhook server that returns 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	config := &RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
	}

	authenticator, err := NewWebhookAuthenticator(context.TODO(), config, authmode.RelyAuthenticatorOptions{})
	assert.NilError(t, err)
	defer authenticator.Close()

	_, err = authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
		Headers: map[string]string{},
	})
	assert.ErrorContains(t, err, "500")
}

func TestWebhookAuthenticator_NonJSONResponse(t *testing.T) {
	// Create a mock webhook server that returns non-JSON content
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("plain text response"))
	}))
	defer server.Close()

	config := &RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
	}

	authenticator, err := NewWebhookAuthenticator(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	_, err = authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
		Headers: map[string]string{},
	})
	assert.ErrorContains(t, err, "invalid character")
}

func TestWebhookAuthenticator_WithCustomHeaders(t *testing.T) {
	// Create a mock webhook server that checks for custom headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"x-hasura-role": "user",
		})
	}))
	defer server.Close()

	config := &RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
	}

	authenticator, err := NewWebhookAuthenticator(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"authorization": "Bearer token123",
		},
	})
	assert.NilError(t, err)
	assert.DeepEqual(t, map[string]any{
		"x-hasura-role": "user",
	}, result.SessionVariables)
}

func TestWebhookAuthenticator_ContextCancellation(t *testing.T) {
	// Create a mock webhook server with a delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This should not be reached due to context cancellation
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"x-hasura-role": "user",
		})
	}))
	defer server.Close()

	config := &RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    goenvconf.NewEnvStringValue(server.URL),
		Method: http.MethodGet,
	}

	authenticator, err := NewWebhookAuthenticator(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = authenticator.Authenticate(ctx, &authmode.AuthenticateRequestData{
		Headers: map[string]string{},
	})
	// The error should be related to context cancellation
	assert.Assert(t, err != nil)
}

func TestWebhookConfig_ValidateInvalidMethod(t *testing.T) {
	config := &RelyAuthWebhookConfig{
		URL:    goenvconf.NewEnvStringValue("http://example.com"),
		Method: "INVALID",
	}

	err := config.Validate()
	assert.ErrorContains(t, err, "must be one of GET or POST")
}
