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

var testAuthConfigWithSecurityRules = `
mode: apiKey
tokenLocation:
  in: header
  name: Authorization
value:
  value: secret
securityRules:
  allowedIPs:
    include:
      value:
        - 192.168.1.0/24
  headerRules:
    Authorization:
      include:
        value:
          - "^Bearer .*"
      exclude:
        value:
          - ".*test.*"
`

func TestRelyAuthConfig_Validate(t *testing.T) {
	testCases := []struct {
		Name        string
		Config      RelyAuthConfig
		ExpectError string
	}{
		{
			Name: "valid_config_with_multiple_modes",
			Config: RelyAuthConfig{
				Definition: RelyAuthDefinition{
					Modes: []RelyAuthMode{
						{
							RelyAuthModeInterface: &apikey.RelyAuthAPIKeyConfig{
								Mode: authmode.AuthModeAPIKey,
								TokenLocation: authscheme.TokenLocation{
									In:   authscheme.InHeader,
									Name: "Authorization",
								},
								Value: goenvconf.NewEnvStringValue("secret"),
							},
						},
						{
							RelyAuthModeInterface: &noauth.RelyAuthNoAuthConfig{
								Mode: authmode.AuthModeNoAuth,
							},
						},
					},
				},
			},
			ExpectError: "",
		},
		{
			Name: "multiple_noauth_not_allowed",
			Config: RelyAuthConfig{
				Definition: RelyAuthDefinition{
					Modes: []RelyAuthMode{
						{
							RelyAuthModeInterface: &noauth.RelyAuthNoAuthConfig{
								Mode: authmode.AuthModeNoAuth,
							},
						},
						{
							RelyAuthModeInterface: &noauth.RelyAuthNoAuthConfig{
								Mode: authmode.AuthModeNoAuth,
							},
						},
					},
				},
			},
			ExpectError: authmode.ErrOnlyOneNoAuthModeAllowed.Error(),
		},
		{
			Name: "invalid_definition",
			Config: RelyAuthConfig{
				Definition: RelyAuthDefinition{
					Modes: []RelyAuthMode{
						{
							RelyAuthModeInterface: nil,
						},
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

func TestRelyAuthMode_UnmarshalJSON(t *testing.T) {
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
				"tokenLocation": {
					"in": "header",
					"name": "Authorization"
				},
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
			var def RelyAuthMode
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

func TestRelyAuthMode_UnmarshalYAML(t *testing.T) {
	testCases := []struct {
		Name                string
		YAML                string
		ExpectMode          authmode.AuthMode
		ExpectSecurityRules bool
		ExpectError         string
	}{
		{
			Name: "apikey_mode",
			YAML: `
mode: apiKey
tokenLocation:
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
			Name: "jwt_mode",
			YAML: `
mode: jwt
tokenLocation:
  in: header
  name: Authorization
key:
  algorithm: HS256
  key:
    value: secret
claimsConfig:
  locations:
    x-hasura-role:
      default:
        value: user
`,
			ExpectMode: authmode.AuthModeJWT,
		},
		{
			Name: "webhook_mode",
			YAML: `
mode: webhook
url:
  value: http://example.com
method: POST
`,
			ExpectMode: authmode.AuthModeWebhook,
		},
		{
			Name: "apikey_mode_with_allowed_ips_security_rules",
			YAML: `
mode: apiKey
tokenLocation:
  in: header
  name: Authorization
value:
  value: secret
securityRules:
  allowedIPs:
    include:
      value:
        - 192.168.1.0/24
        - 10.0.0.0/8
    headers:
      - X-Forwarded-For
`,
			ExpectMode:          authmode.AuthModeAPIKey,
			ExpectSecurityRules: true,
		},
		{
			Name: "apikey_mode_with_header_rules_security_rules",
			YAML: `
mode: apiKey
tokenLocation:
  in: header
  name: Authorization
value:
  value: secret
securityRules:
  headerRules:
    Authorization:
      include:
        value:
          - "^Bearer .*"
`,
			ExpectMode:          authmode.AuthModeAPIKey,
			ExpectSecurityRules: true,
		},
		{
			Name:                "apikey_mode_with_combined_security_rules",
			YAML:                testAuthConfigWithSecurityRules,
			ExpectMode:          authmode.AuthModeAPIKey,
			ExpectSecurityRules: true,
		},
		{
			Name: "noauth_mode_with_security_rules",
			YAML: `
mode: noAuth
sessionVariables: {}
securityRules:
  allowedIPs:
    include:
      value:
        - 10.0.0.0/8
`,
			ExpectMode:          authmode.AuthModeNoAuth,
			ExpectSecurityRules: true,
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
			var def RelyAuthMode
			err := yaml.Unmarshal([]byte(tc.YAML), &def)
			if tc.ExpectError != "" {
				assert.ErrorContains(t, err, tc.ExpectError)
			} else {
				assert.NilError(t, err)
				assert.Equal(t, tc.ExpectMode, def.GetMode())
				if tc.ExpectSecurityRules {
					assert.Assert(t, def.SecurityRules != nil)
				} else {
					assert.Assert(t, def.SecurityRules == nil)
				}
			}
		})
	}
}
