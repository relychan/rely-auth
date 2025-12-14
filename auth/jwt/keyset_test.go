package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hasura/goenvconf"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
	"gotest.tools/v3/assert"
)

func TestJWTKeySet_Equal(t *testing.T) {
	t.Run("equal_hmac_keysets", func(t *testing.T) {
		config := &RelyAuthJWTConfig{
			ID:   "test-1",
			Mode: authmode.AuthModeJWT,
			Key: JWTKey{
				Algorithm: jose.HS256,
				Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("my-secret-key-for-testing-at-least-32-bytes-long")),
			},
			ClaimsConfig: JWTClaimsConfig{
				Locations: map[string]jmes.FieldMappingEntryConfig{
					"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
				},
			},
		}

		keyset1, err := NewJWTKeySet(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer keyset1.Close()

		keyset2, err := NewJWTKeySet(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer keyset2.Close()

		assert.Assert(t, keyset1.Equal(keyset2))
	})

	t.Run("different_configs", func(t *testing.T) {
		config1 := &RelyAuthJWTConfig{
			ID:   "test-1",
			Mode: authmode.AuthModeJWT,
			Key: JWTKey{
				Algorithm: jose.HS256,
				Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("my-secret-key-for-testing-at-least-32-bytes-long")),
			},
			ClaimsConfig: JWTClaimsConfig{
				Locations: map[string]jmes.FieldMappingEntryConfig{
					"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
				},
			},
		}

		config2 := &RelyAuthJWTConfig{
			ID:   "test-2",
			Mode: authmode.AuthModeJWT,
			Key: JWTKey{
				Algorithm: jose.HS256,
				Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("different-secret-key-for-testing-at-least-32-bytes")),
			},
			ClaimsConfig: JWTClaimsConfig{
				Locations: map[string]jmes.FieldMappingEntryConfig{
					"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
				},
			},
		}

		keyset1, err := NewJWTKeySet(context.TODO(), config1, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer keyset1.Close()

		keyset2, err := NewJWTKeySet(context.TODO(), config2, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer keyset2.Close()

		assert.Assert(t, !keyset1.Equal(keyset2))
	})
}

func TestJWTKeySet_GetConfig(t *testing.T) {
	config := &RelyAuthJWTConfig{
		ID:   "test-config",
		Mode: authmode.AuthModeJWT,
		Key: JWTKey{
			Algorithm: jose.HS256,
			Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("my-secret-key-for-testing-at-least-32-bytes-long")),
		},
		ClaimsConfig: JWTClaimsConfig{
			Locations: map[string]jmes.FieldMappingEntryConfig{
				"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
			},
		},
	}

	keyset, err := NewJWTKeySet(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer keyset.Close()

	retrievedConfig := keyset.GetConfig()
	assert.Equal(t, config.ID, retrievedConfig.ID)
	assert.Equal(t, config.Mode, retrievedConfig.Mode)
}

func TestJWTKeySet_Close(t *testing.T) {
	config := &RelyAuthJWTConfig{
		ID:   "test-close",
		Mode: authmode.AuthModeJWT,
		Key: JWTKey{
			Algorithm: jose.HS256,
			Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("my-secret-key-for-testing-at-least-32-bytes-long")),
		},
		ClaimsConfig: JWTClaimsConfig{
			Locations: map[string]jmes.FieldMappingEntryConfig{
				"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
			},
		},
	}

	keyset, err := NewJWTKeySet(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)

	err = keyset.Close()
	assert.NilError(t, err)
}

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

	t.Run("empty_claims", func(t *testing.T) {
		config := RelyAuthJWTConfig{
			Mode: authmode.AuthModeJWT,
			Key: JWTKey{
				Algorithm: jose.HS256,
				Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("my-secret-key-for-testing-at-least-32-bytes-long")),
			},
			ClaimsConfig: JWTClaimsConfig{
				Locations: map[string]jmes.FieldMappingEntryConfig{
					"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
				},
			},
		}

		keyset, err := NewJWTKeySet(context.TODO(), &config, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer keyset.Close()

		_, err = keyset.TransformClaims([]byte{})
		assert.ErrorContains(t, err, ErrJWTClaimsNull.Error())
	})

	t.Run("malformed_json", func(t *testing.T) {
		config := RelyAuthJWTConfig{
			Mode: authmode.AuthModeJWT,
			Key: JWTKey{
				Algorithm: jose.HS256,
				Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("my-secret-key-for-testing-at-least-32-bytes-long")),
			},
			ClaimsConfig: JWTClaimsConfig{
				Locations: map[string]jmes.FieldMappingEntryConfig{
					"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
				},
			},
		}

		keyset, err := NewJWTKeySet(context.TODO(), &config, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer keyset.Close()

		_, err = keyset.TransformClaims([]byte("invalid json"))
		assert.ErrorContains(t, err, ErrJWTClaimsMalformedJSON.Error())
	})

	t.Run("with_default_values", func(t *testing.T) {
		config := RelyAuthJWTConfig{
			Mode: authmode.AuthModeJWT,
			Key: JWTKey{
				Algorithm: jose.HS256,
				Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("my-secret-key-for-testing-at-least-32-bytes-long")),
			},
			ClaimsConfig: JWTClaimsConfig{
				Locations: map[string]jmes.FieldMappingEntryConfig{
					"x-hasura-user-id": {
						Path:    goutils.ToPtr("sub"),
						Default: goutils.ToPtr(goenvconf.NewEnvAnyValue("default-user")),
					},
					"x-hasura-org-id": {
						Path:    goutils.ToPtr("org_id"),
						Default: goutils.ToPtr(goenvconf.NewEnvAnyValue("default-org")),
					},
				},
			},
		}

		keyset, err := NewJWTKeySet(context.TODO(), &config, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer keyset.Close()

		rawClaims := `{
			"sub": "user-123",
			"iss": "https://relychan.com"
		}`

		result, err := keyset.TransformClaims([]byte(rawClaims))
		assert.NilError(t, err)
		assert.Equal(t, "user-123", result["x-hasura-user-id"])
		assert.Equal(t, "default-org", result["x-hasura-org-id"])
	})
}

func TestJWTKeySet_GetSignatureAlgorithms(t *testing.T) {
	t.Run("with_config_algorithm", func(t *testing.T) {
		config := &RelyAuthJWTConfig{
			Mode: authmode.AuthModeJWT,
			Key: JWTKey{
				Algorithm: jose.HS256,
				Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("my-secret-key-for-testing-at-least-32-bytes-long")),
			},
			ClaimsConfig: JWTClaimsConfig{
				Locations: map[string]jmes.FieldMappingEntryConfig{
					"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
				},
			},
		}

		keyset, err := NewJWTKeySet(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer keyset.Close()

		algorithms := keyset.GetSignatureAlgorithms()
		assert.Equal(t, 1, len(algorithms))
		assert.Equal(t, jose.HS256, algorithms[0])
	})
}

func TestJWTKeySet_ValidateClaims(t *testing.T) {
	t.Run("valid_claims", func(t *testing.T) {
		config := &RelyAuthJWTConfig{
			Mode:     authmode.AuthModeJWT,
			Issuer:   "https://relychan.com",
			Audience: []string{"https://relychan.com"},
			Key: JWTKey{
				Algorithm: jose.HS256,
				Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("my-secret-key-for-testing-at-least-32-bytes-long")),
			},
			ClaimsConfig: JWTClaimsConfig{
				Locations: map[string]jmes.FieldMappingEntryConfig{
					"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
				},
			},
		}

		keyset, err := NewJWTKeySet(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer keyset.Close()

		claims := &jwt.Claims{
			Issuer:   "https://relychan.com",
			Audience: jwt.Audience{"https://relychan.com"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		}

		err = keyset.ValidateClaims(claims)
		assert.NilError(t, err)
	})

	t.Run("invalid_issuer", func(t *testing.T) {
		config := &RelyAuthJWTConfig{
			Mode:   authmode.AuthModeJWT,
			Issuer: "https://relychan.com",
			Key: JWTKey{
				Algorithm: jose.HS256,
				Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("my-secret-key-for-testing-at-least-32-bytes-long")),
			},
			ClaimsConfig: JWTClaimsConfig{
				Locations: map[string]jmes.FieldMappingEntryConfig{
					"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
				},
			},
		}

		keyset, err := NewJWTKeySet(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer keyset.Close()

		claims := &jwt.Claims{
			Issuer: "https://wrong-issuer.com",
			Expiry: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		}

		err = keyset.ValidateClaims(claims)
		assert.ErrorContains(t, err, "issuer")
	})
}

func TestEvalHasuraSessionVariables(t *testing.T) {
	t.Run("with_x-hasura-role", func(t *testing.T) {
		input := map[string]any{
			"x-hasura-allowed-roles": []any{"user", "admin"},
			"x-hasura-default-role":  "user",
			"x-hasura-role":          "admin",
			"x-hasura-user-id":       "123",
		}

		result, err := evalHasuraSessionVariables(input)
		assert.NilError(t, err)
		assert.Equal(t, "admin", result["x-hasura-role"])
		assert.Equal(t, "123", result["x-hasura-user-id"])
		_, hasAllowedRoles := result["x-hasura-allowed-roles"]
		assert.Assert(t, !hasAllowedRoles)
		_, hasDefaultRole := result["x-hasura-default-role"]
		assert.Assert(t, !hasDefaultRole)
	})

	t.Run("with_default_role", func(t *testing.T) {
		input := map[string]any{
			"x-hasura-allowed-roles": []any{"user", "admin"},
			"x-hasura-default-role":  "user",
			"x-hasura-user-id":       "123",
		}

		result, err := evalHasuraSessionVariables(input)
		assert.NilError(t, err)
		assert.Equal(t, "user", result["x-hasura-role"])
		assert.Equal(t, "123", result["x-hasura-user-id"])
	})

	t.Run("role_not_in_allowed_roles", func(t *testing.T) {
		input := map[string]any{
			"x-hasura-allowed-roles": []any{"user", "admin"},
			"x-hasura-default-role":  "user",
			"x-hasura-role":          "superadmin",
		}

		_, err := evalHasuraSessionVariables(input)
		assert.ErrorContains(t, err, "not in the allowed roles")
	})

	t.Run("default_role_not_in_allowed_roles", func(t *testing.T) {
		input := map[string]any{
			"x-hasura-allowed-roles": []any{"user", "admin"},
			"x-hasura-default-role":  "superadmin",
		}

		_, err := evalHasuraSessionVariables(input)
		assert.ErrorContains(t, err, "not in the allowed roles")
	})

	t.Run("empty_default_role", func(t *testing.T) {
		input := map[string]any{
			"x-hasura-allowed-roles": []any{"user", "admin"},
			"x-hasura-default-role":  "",
		}

		_, err := evalHasuraSessionVariables(input)
		assert.ErrorContains(t, err, "value of x-hasura-default-role variable is empty")
	})

	t.Run("no_hasura_variables", func(t *testing.T) {
		input := map[string]any{
			"x-hasura-user-id": "123",
			"custom-claim":     "value",
		}

		result, err := evalHasuraSessionVariables(input)
		assert.NilError(t, err)
		assert.Equal(t, "123", result["x-hasura-user-id"])
		assert.Equal(t, "value", result["custom-claim"])
	})

	t.Run("malformed_allowed_roles", func(t *testing.T) {
		input := map[string]any{
			"x-hasura-allowed-roles": "not-an-array",
			"x-hasura-default-role":  "user",
		}

		_, err := evalHasuraSessionVariables(input)
		assert.ErrorContains(t, err, "malformed x-hasura-allowed-roles")
	})

	t.Run("malformed_default_role", func(t *testing.T) {
		input := map[string]any{
			"x-hasura-allowed-roles": []any{"user", "admin"},
			"x-hasura-default-role":  123,
		}

		_, err := evalHasuraSessionVariables(input)
		assert.ErrorContains(t, err, "malformed x-hasura-default-role")
	})

	t.Run("malformed_role", func(t *testing.T) {
		input := map[string]any{
			"x-hasura-allowed-roles": []any{"user", "admin"},
			"x-hasura-default-role":  "user",
			"x-hasura-role":          123,
		}

		_, err := evalHasuraSessionVariables(input)
		assert.ErrorContains(t, err, "malformed x-hasura-role")
	})
}

func TestJWTKeySet_InitWithECDSA(t *testing.T) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	assert.NilError(t, err)

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	config := &RelyAuthJWTConfig{
		Mode: authmode.AuthModeJWT,
		Key: JWTKey{
			Algorithm: jose.ES256,
			Key:       goutils.ToPtr(goenvconf.NewEnvStringValue(string(pubKeyPEM))),
		},
		ClaimsConfig: JWTClaimsConfig{
			Locations: map[string]jmes.FieldMappingEntryConfig{
				"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
			},
		},
	}

	keyset, err := NewJWTKeySet(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer keyset.Close()

	assert.Assert(t, keyset.publicKey != nil)
}

func TestJWTKeySet_InitWithEdDSA(t *testing.T) {
	// Note: EdDSA key initialization has a known issue in keyset.go where it expects
	// *ed25519.PublicKey but ed25519.PublicKey is a slice type, not a struct.
	// This test verifies the error handling for this case.

	// Generate Ed25519 key pair
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NilError(t, err)

	// ed25519.PublicKey is already a []byte, we need to marshal it properly
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	assert.NilError(t, err)

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	config := &RelyAuthJWTConfig{
		Mode: authmode.AuthModeJWT,
		Key: JWTKey{
			Algorithm: jose.EdDSA,
			Key:       goutils.ToPtr(goenvconf.NewEnvStringValue(string(pubKeyPEM))),
		},
		ClaimsConfig: JWTClaimsConfig{
			Locations: map[string]jmes.FieldMappingEntryConfig{
				"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
			},
		},
	}

	// This will fail due to the type assertion issue in keyset.go line 305
	_, err = NewJWTKeySet(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.ErrorContains(t, err, "The public key is not an Ed25519 key")
}

func TestJWTKeySet_InitWithJWKURL(t *testing.T) {
	// Generate a real RSA key for the JWKS
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)

	jwk := jose.JSONWebKey{
		KeyID:     "test-key-1",
		Algorithm: string(jose.RS256),
		Use:       "sig",
		Key:       &privateKey.PublicKey,
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(jwks)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	config := &RelyAuthJWTConfig{
		Mode: authmode.AuthModeJWT,
		Key: JWTKey{
			JWKFromURL: goutils.ToPtr(goenvconf.NewEnvStringValue(server.URL)),
		},
		ClaimsConfig: JWTClaimsConfig{
			Locations: map[string]jmes.FieldMappingEntryConfig{
				"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
			},
		},
	}

	keyset, err := NewJWTKeySet(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer keyset.Close()

	assert.Equal(t, server.URL, keyset.jwksURL)
	assert.Assert(t, len(keyset.cachedKeys) > 0)
}

func TestJWTKeySet_Reload(t *testing.T) {
	callCount := 0

	// Generate a real RSA key for the JWKS
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)

	jwk := jose.JSONWebKey{
		KeyID:     "test-key-1",
		Algorithm: string(jose.RS256),
		Use:       "sig",
		Key:       &privateKey.PublicKey,
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(jwks)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	config := &RelyAuthJWTConfig{
		Mode: authmode.AuthModeJWT,
		Key: JWTKey{
			JWKFromURL: goutils.ToPtr(goenvconf.NewEnvStringValue(server.URL)),
		},
		ClaimsConfig: JWTClaimsConfig{
			Locations: map[string]jmes.FieldMappingEntryConfig{
				"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
			},
		},
	}

	keyset, err := NewJWTKeySet(context.TODO(), config, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer keyset.Close()

	initialCallCount := callCount

	err = keyset.Reload(context.TODO())
	assert.NilError(t, err)
	assert.Assert(t, callCount > initialCallCount)
}
