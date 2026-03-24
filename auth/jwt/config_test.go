// Copyright 2026 RelyChan Pte. Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jwt

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/hasura/goenvconf"
	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/rely-auth/auth/authmode"
	"github.com/stretchr/testify/assert"
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
					Key:       new(goenvconf.NewEnvStringValue("secret")),
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
					Key:       new(goenvconf.NewEnvStringValue("secret")),
				},
				ClaimsConfig: JWTClaimsConfig{
					Locations: map[string]jmes.FieldMappingEntryConfig{
						"x-hasura-user-id": {
							Path: new("sub"),
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
					Key:       new(goenvconf.NewEnvStringValue("secret")),
				},
				ClaimsConfig: JWTClaimsConfig{},
			},
			ExpectError: ErrJWTClaimsConfigEmpty.Error(),
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
					Key:       new(goenvconf.NewEnvStringValue("secret")),
				},
				ClaimsConfig: JWTClaimsConfig{
					Locations: map[string]jmes.FieldMappingEntryConfig{
						"x-hasura-user-id": {
							Path: new("sub"),
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
				assert.NoError(t, err)
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
		Key:       new(goenvconf.NewEnvStringValue("secret")),
	}
	tokenLocation := authscheme.TokenLocation{
		In:   authscheme.InHeader,
		Name: "Authorization",
	}

	config := NewRelyAuthJWTConfig(key, tokenLocation)
	assert.True(t, config != nil)
	assert.Equal(t, key, config.Key)
	assert.Equal(t, tokenLocation, config.TokenLocation)
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
				Key:       new(goenvconf.NewEnvStringValue("secret")),
			},
			ExpectError: "",
		},
		{
			Name: "valid_with_jwk_url",
			Key: JWTKey{
				JWKFromURL: new(goenvconf.NewEnvStringValue("https://example.com/.well-known/jwks.json")),
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
				Key:       new(goenvconf.NewEnvStringValue("secret")),
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
				assert.NoError(t, err)
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
						Path: new("sub"),
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
				assert.NoError(t, err)
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
				assert.NoError(t, err)
			}
		})
	}
}
