package jwt

import (
	"context"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/hasura/goenvconf"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
	"gotest.tools/v3/assert"
)

func TestTransformJWTClaims(t *testing.T) {
	t.Run("namespace_json", func(t *testing.T) {
		config := RelyAuthJWTConfig{
			Mode: authmode.AuthModeJWT,
			Key: JWTKey{
				Algorithm: jose.HS256,
				Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("randomsecretkey")),
			},
			ClaimsConfig: JWTClaimsConfig{
				Namespace: &JWTClaimsNamespace{
					Location:     `"claims.jwt.hasura.io"`,
					ClaimsFormat: JWTClaimsFormatJSON,
				},
				Locations: map[string]jmes.FieldMappingEntryConfig{
					"x-hasura-user-id": {
						Path: goutils.ToPtr("sub"),
					},
				},
			},
		}

		keyset, err := NewJWTKeySet(context.TODO(), &config, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)

		rawClaims := `{
			"claims.jwt.hasura.io": {
				"x-hasura-allowed-roles": [
					"user", "admin"
				],
				"x-hasura-default-role": "user"
			},
			"iss": "https://relychan.com",
			"sub": "user-id",
			"aud": "https://relychan.com",
			"iat": 1760939954,
			"exp": 9761026354
		}`

		result, err := keyset.TransformClaims([]byte(rawClaims))
		assert.NilError(t, err)

		expected := map[string]any{
			"x-hasura-role":    "user",
			"x-hasura-user-id": "user-id",
		}

		assert.DeepEqual(t, result, expected)
	})

	t.Run("namespace_stringified_json", func(t *testing.T) {
		config := RelyAuthJWTConfig{
			Mode: authmode.AuthModeJWT,
			Key: JWTKey{
				Algorithm: jose.HS256,
				Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("randomsecretkey")),
			},
			ClaimsConfig: JWTClaimsConfig{
				Namespace: &JWTClaimsNamespace{
					Location:     `"claims.jwt.hasura.io"`,
					ClaimsFormat: JWTClaimsFormatStringifiedJSON,
				},
				Locations: map[string]jmes.FieldMappingEntryConfig{
					"x-hasura-user-id": {
						Path: goutils.ToPtr("sub"),
					},
				},
			},
		}

		keyset, err := NewJWTKeySet(context.TODO(), &config, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)

		rawClaims := `{
			"claims.jwt.hasura.io": "{\"x-hasura-allowed-roles\": [\"user\", \"admin\"],\"x-hasura-role\": \"user\"}",
			"iss": "https://relychan.com",
			"sub": "user-id",
			"aud": "https://relychan.com",
			"iat": 1760939954,
			"exp": 9761026354
		}`

		result, err := keyset.TransformClaims([]byte(rawClaims))
		assert.NilError(t, err)

		expected := map[string]any{
			"x-hasura-role":    "user",
			"x-hasura-user-id": "user-id",
		}

		assert.DeepEqual(t, result, expected)
	})
}
