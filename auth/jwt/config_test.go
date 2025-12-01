package jwt

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/hasura/goenvconf"
	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
	"gotest.tools/v3/assert"
)

func TestRelyAuthJWTConfig_Validate(t *testing.T) {
	testCases := []struct {
		Name        string
		Config      RelyAuthJWTConfig
		ExpectError string
	}{
		{
			Name: "valid_config_with_namespace",
			Config: RelyAuthJWTConfig{
				Mode: authmode.AuthModeJWT,
				TokenLocation: authscheme.TokenLocation{
					In:   authscheme.InHeader,
					Name: "Authorization",
				},
				Key: JWTKey{
					Algorithm: jose.HS256,
					Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("secret")),
				},
				ClaimsConfig: JWTClaimsConfig{
					Namespace: &JWTClaimsNamespace{
						Location:     `"claims"`,
						ClaimsFormat: JWTClaimsFormatJSON,
					},
				},
			},
			ExpectError: "",
		},
		{
			Name: "valid_config_with_locations",
			Config: RelyAuthJWTConfig{
				Mode: authmode.AuthModeJWT,
				TokenLocation: authscheme.TokenLocation{
					In:   authscheme.InHeader,
					Name: "Authorization",
				},
				Key: JWTKey{
					Algorithm: jose.HS256,
					Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("secret")),
				},
				ClaimsConfig: JWTClaimsConfig{
					Locations: map[string]jmes.FieldMappingEntryConfig{
						"x-hasura-user-id": {
							Path: goutils.ToPtr("sub"),
						},
					},
				},
			},
			ExpectError: "",
		},
		{
			Name: "invalid_empty_claims_config",
			Config: RelyAuthJWTConfig{
				Mode: authmode.AuthModeJWT,
				TokenLocation: authscheme.TokenLocation{
					In:   authscheme.InHeader,
					Name: "Authorization",
				},
				Key: JWTKey{
					Algorithm: jose.HS256,
					Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("secret")),
				},
				ClaimsConfig: JWTClaimsConfig{},
			},
			ExpectError: ErrJWTClaimsConfigEmpty.Error(),
		},
		{
			Name: "invalid_token_location",
			Config: RelyAuthJWTConfig{
				Mode: authmode.AuthModeJWT,
				TokenLocation: authscheme.TokenLocation{
					In: "invalid",
				},
				Key: JWTKey{
					Algorithm: jose.HS256,
					Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("secret")),
				},
				ClaimsConfig: JWTClaimsConfig{
					Locations: map[string]jmes.FieldMappingEntryConfig{
						"x-hasura-user-id": {
							Path: goutils.ToPtr("sub"),
						},
					},
				},
			},
			ExpectError: "invalid",
		},
		{
			Name: "invalid_key_algorithm",
			Config: RelyAuthJWTConfig{
				Mode: authmode.AuthModeJWT,
				TokenLocation: authscheme.TokenLocation{
					In:   authscheme.InHeader,
					Name: "Authorization",
				},
				Key: JWTKey{
					Algorithm: "INVALID",
					Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("secret")),
				},
				ClaimsConfig: JWTClaimsConfig{
					Locations: map[string]jmes.FieldMappingEntryConfig{
						"x-hasura-user-id": {
							Path: goutils.ToPtr("sub"),
						},
					},
				},
			},
			ExpectError: ErrInvalidSignatureAlgorithm.Error(),
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

func TestRelyAuthJWTConfig_GetMode(t *testing.T) {
	config := RelyAuthJWTConfig{}
	assert.Equal(t, authmode.AuthModeJWT, config.GetMode())
}

func TestNewJWTAuthDefinition(t *testing.T) {
	key := JWTKey{
		Algorithm: jose.HS256,
		Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("secret")),
	}
	tokenLocation := authscheme.TokenLocation{
		In:   authscheme.InHeader,
		Name: "Authorization",
	}

	config := NewJWTAuthDefinition(key, tokenLocation)
	assert.Assert(t, config != nil)
	assert.Equal(t, key, config.Key)
	assert.DeepEqual(t, tokenLocation, config.TokenLocation)
}

func TestJWTKey_Validate(t *testing.T) {
	testCases := []struct {
		Name        string
		Key         JWTKey
		ExpectError string
	}{
		{
			Name: "valid_with_key",
			Key: JWTKey{
				Algorithm: jose.HS256,
				Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("secret")),
			},
			ExpectError: "",
		},
		{
			Name: "valid_with_jwk_url",
			Key: JWTKey{
				JWKFromURL: goutils.ToPtr(goenvconf.NewEnvStringValue("https://example.com/.well-known/jwks.json")),
			},
			ExpectError: "",
		},
		{
			Name: "invalid_no_key_or_url",
			Key: JWTKey{
				Algorithm: jose.HS256,
			},
			ExpectError: ErrJWTAuthKeyRequired.Error(),
		},
		{
			Name: "invalid_algorithm_with_key",
			Key: JWTKey{
				Algorithm: "INVALID",
				Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("secret")),
			},
			ExpectError: ErrInvalidSignatureAlgorithm.Error(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			err := tc.Key.Validate()
			if tc.ExpectError != "" {
				assert.ErrorContains(t, err, tc.ExpectError)
			} else {
				assert.NilError(t, err)
			}
		})
	}
}

func TestJWTClaimsConfig_Validate(t *testing.T) {
	testCases := []struct {
		Name        string
		Config      JWTClaimsConfig
		ExpectError string
	}{
		{
			Name: "valid_with_namespace",
			Config: JWTClaimsConfig{
				Namespace: &JWTClaimsNamespace{
					Location:     `"claims"`,
					ClaimsFormat: JWTClaimsFormatJSON,
				},
			},
			ExpectError: "",
		},
		{
			Name: "valid_with_locations",
			Config: JWTClaimsConfig{
				Locations: map[string]jmes.FieldMappingEntryConfig{
					"x-hasura-user-id": {
						Path: goutils.ToPtr("sub"),
					},
				},
			},
			ExpectError: "",
		},
		{
			Name:        "invalid_empty",
			Config:      JWTClaimsConfig{},
			ExpectError: ErrJWTClaimsConfigEmpty.Error(),
		},
		{
			Name: "invalid_claims_format",
			Config: JWTClaimsConfig{
				Namespace: &JWTClaimsNamespace{
					Location:     `"claims"`,
					ClaimsFormat: "Invalid",
				},
			},
			ExpectError: ErrInvalidJWTClaimsFormat.Error(),
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

func TestJWTClaimsNamespace_Validate(t *testing.T) {
	testCases := []struct {
		Name        string
		Namespace   JWTClaimsNamespace
		ExpectError string
	}{
		{
			Name: "valid_json",
			Namespace: JWTClaimsNamespace{
				Location:     `"claims"`,
				ClaimsFormat: JWTClaimsFormatJSON,
			},
			ExpectError: "",
		},
		{
			Name: "valid_stringified_json",
			Namespace: JWTClaimsNamespace{
				Location:     `"claims"`,
				ClaimsFormat: JWTClaimsFormatStringifiedJSON,
			},
			ExpectError: "",
		},
		{
			Name: "invalid_format",
			Namespace: JWTClaimsNamespace{
				Location:     `"claims"`,
				ClaimsFormat: "Invalid",
			},
			ExpectError: ErrInvalidJWTClaimsFormat.Error(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			err := tc.Namespace.Validate()
			if tc.ExpectError != "" {
				assert.ErrorContains(t, err, tc.ExpectError)
			} else {
				assert.NilError(t, err)
			}
		})
	}
}
