package auth

import (
	"encoding/json"
	"testing"

	"github.com/hasura/goenvconf"
	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/rely-auth/auth/apikey"
	"github.com/relychan/rely-auth/auth/authmode"
	"github.com/relychan/rely-auth/auth/noauth"
	"go.yaml.in/yaml/v4"
	"gotest.tools/v3/assert"
)

func TestRelyAuthConfig_Validate(t *testing.T) {
	testCases := []struct {
		Name        string
		Config      RelyAuthConfig
		ExpectError string
	}{
		{
			Name: "valid_config_with_multiple_modes",
			Config: RelyAuthConfig{
				Definitions: []RelyAuthDefinition{
					{
						RelyAuthDefinitionInterface: &apikey.RelyAuthAPIKeyConfig{
							Mode: authmode.AuthModeAPIKey,
							TokenLocation: authscheme.TokenLocation{
								In:   authscheme.InHeader,
								Name: "Authorization",
							},
							Value: goenvconf.NewEnvStringValue("secret"),
						},
					},
					{
						RelyAuthDefinitionInterface: &noauth.RelyAuthNoAuthConfig{
							Mode: authmode.AuthModeNoAuth,
						},
					},
				},
			},
			ExpectError: "",
		},
		{
			Name: "multiple_noauth_not_allowed",
			Config: RelyAuthConfig{
				Definitions: []RelyAuthDefinition{
					{
						RelyAuthDefinitionInterface: &noauth.RelyAuthNoAuthConfig{
							Mode: authmode.AuthModeNoAuth,
						},
					},
					{
						RelyAuthDefinitionInterface: &noauth.RelyAuthNoAuthConfig{
							Mode: authmode.AuthModeNoAuth,
						},
					},
				},
			},
			ExpectError: authmode.ErrOnlyOneNoAuthModeAllowed.Error(),
		},
		{
			Name: "invalid_definition",
			Config: RelyAuthConfig{
				Definitions: []RelyAuthDefinition{
					{
						RelyAuthDefinitionInterface: nil,
					},
				},
			},
			ExpectError: authmode.ErrAuthConfigRequired.Error(),
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

func TestRelyAuthDefinition_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		Name        string
		JSON        string
		ExpectMode  authmode.AuthMode
		ExpectError string
	}{
		{
			Name: "apikey_mode",
			JSON: `{
				"mode": "apiKey",
				"in": "header",
				"name": "Authorization",
				"value": {"value": "secret"}
			}`,
			ExpectMode: authmode.AuthModeAPIKey,
		},
		{
			Name: "jwt_mode",
			JSON: `{
				"mode": "jwt",
				"tokenLocation": {
					"in": "header",
					"name": "Authorization"
				},
				"key": {
					"algorithm": "HS256",
					"key": {"value": "secret"}
				},
				"claimsConfig": {
					"locations": {
						"x-hasura-role": {
							"default": {"value": "user"}
						}
					}
				}
			}`,
			ExpectMode: authmode.AuthModeJWT,
		},
		{
			Name: "webhook_mode",
			JSON: `{
				"mode": "webhook",
				"url": {"value": "http://example.com"},
				"method": "POST"
			}`,
			ExpectMode: authmode.AuthModeWebhook,
		},
		{
			Name: "noauth_mode",
			JSON: `{
				"mode": "noAuth",
				"sessionVariables": {}
			}`,
			ExpectMode: authmode.AuthModeNoAuth,
		},
		{
			Name: "unsupported_mode",
			JSON: `{
				"mode": "unsupported"
			}`,
			ExpectError: authmode.ErrUnsupportedAuthMode.Error(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			var def RelyAuthDefinition
			err := json.Unmarshal([]byte(tc.JSON), &def)
			if tc.ExpectError != "" {
				assert.ErrorContains(t, err, tc.ExpectError)
			} else {
				assert.NilError(t, err)
				assert.Equal(t, tc.ExpectMode, def.GetMode())
			}
		})
	}
}

func TestRelyAuthDefinition_UnmarshalYAML(t *testing.T) {
	testCases := []struct {
		Name        string
		YAML        string
		ExpectMode  authmode.AuthMode
		ExpectError string
	}{
		{
			Name: "apikey_mode",
			YAML: `
mode: apiKey
in: header
name: Authorization
value:
  value: secret
`,
			ExpectMode: authmode.AuthModeAPIKey,
		},
		{
			Name: "noauth_mode",
			YAML: `
mode: noAuth
sessionVariables: {}
`,
			ExpectMode: authmode.AuthModeNoAuth,
		},
		{
			Name: "unsupported_mode",
			YAML: `
mode: invalid
`,
			ExpectError: authmode.ErrUnsupportedAuthMode.Error(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			var def RelyAuthDefinition
			err := yaml.Unmarshal([]byte(tc.YAML), &def)
			if tc.ExpectError != "" {
				assert.ErrorContains(t, err, tc.ExpectError)
			} else {
				assert.NilError(t, err)
				assert.Equal(t, tc.ExpectMode, def.GetMode())
			}
		})
	}
}
