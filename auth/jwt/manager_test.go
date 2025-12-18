package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hasura/goenvconf"
	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
	"gotest.tools/v3/assert"
)

// Helper function to encode RSA public key to PEM format
func encodePublicKeyToPEM(publicKey *rsa.PublicKey) string {
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	return string(pubKeyPEM)
}

func TestNewJWTAuthenticator(t *testing.T) {
	config := RelyAuthJWTConfig{
		ID:   "test-jwt",
		Mode: authmode.AuthModeJWT,
		TokenLocation: authscheme.TokenLocation{
			In:   authscheme.InHeader,
			Name: "Authorization",
		},
		Key: JWTKey{
			Algorithm: jose.HS256,
			Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("test-secret-key")),
		},
		ClaimsConfig: JWTClaimsConfig{
			Locations: map[string]jmes.FieldMappingEntryConfig{
				"x-hasura-user-id": {
					Path: goutils.ToPtr("sub"),
				},
			},
		},
	}

	authenticator, err := NewJWTAuthenticator(context.TODO(), []RelyAuthJWTConfig{config}, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	assert.Assert(t, authenticator != nil)
	defer authenticator.Close()
}

func TestJWTAuthenticator_Mode(t *testing.T) {
	config := RelyAuthJWTConfig{
		Mode: authmode.AuthModeJWT,
		TokenLocation: authscheme.TokenLocation{
			In:   authscheme.InHeader,
			Name: "Authorization",
		},
		Key: JWTKey{
			Algorithm: jose.HS256,
			Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("test-secret")),
		},
		ClaimsConfig: JWTClaimsConfig{
			Locations: map[string]jmes.FieldMappingEntryConfig{
				"x-hasura-user-id": {
					Path: goutils.ToPtr("sub"),
				},
			},
		},
	}

	authenticator, err := NewJWTAuthenticator(context.TODO(), []RelyAuthJWTConfig{config}, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	assert.Equal(t, authmode.AuthModeJWT, authenticator.Mode())
}

func TestJWTAuthenticator_Authenticate_HMAC(t *testing.T) {
	secret := "my-secret-key-for-testing-at-least-32-bytes-long"
	config := RelyAuthJWTConfig{
		ID:   "test-jwt-hmac",
		Mode: authmode.AuthModeJWT,
		TokenLocation: authscheme.TokenLocation{
			In:     authscheme.InHeader,
			Name:   "Authorization",
			Scheme: "Bearer",
		},
		Key: JWTKey{
			Algorithm: jose.HS256,
			Key:       goutils.ToPtr(goenvconf.NewEnvStringValue(secret)),
		},
		ClaimsConfig: JWTClaimsConfig{
			Locations: map[string]jmes.FieldMappingEntryConfig{
				"x-hasura-user-id": {
					Path: goutils.ToPtr("sub"),
				},
				"x-hasura-role": {
					Default: goutils.ToPtr(goenvconf.NewEnvAnyValue("user")),
				},
			},
		},
	}

	authenticator, err := NewJWTAuthenticator(context.TODO(), []RelyAuthJWTConfig{config}, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	// Create a test JWT token
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(secret)}, nil)
	assert.NilError(t, err)

	claims := jwt.Claims{
		Subject:  "user-123",
		Issuer:   "test-issuer",
		Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	assert.NilError(t, err)

	result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"authorization": "Bearer " + token,
		},
	})
	assert.NilError(t, err)
	assert.Equal(t, "test-jwt-hmac", result.ID)
	assert.Equal(t, "user-123", result.SessionVariables["x-hasura-user-id"])
	assert.Equal(t, "user", result.SessionVariables["x-hasura-role"])
}

func TestJWTAuthenticator_Authenticate_Unauthorized(t *testing.T) {
	config := RelyAuthJWTConfig{
		Mode: authmode.AuthModeJWT,
		TokenLocation: authscheme.TokenLocation{
			In:     authscheme.InHeader,
			Name:   "Authorization",
			Scheme: "Bearer",
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
	}

	authenticator, err := NewJWTAuthenticator(context.TODO(), []RelyAuthJWTConfig{config}, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	// Test with invalid token
	_, err = authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"authorization": "Bearer invalid-token",
		},
	})
	assert.Assert(t, err != nil)

	// Test with missing token
	_, err = authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
		Headers: map[string]string{},
	})
	assert.Assert(t, err != nil)
}

func TestJWTAuthenticator_Authenticate_RSA(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)

	publicKeyPEM := encodePublicKeyToPEM(&privateKey.PublicKey)

	config := RelyAuthJWTConfig{
		ID:   "test-jwt-rsa",
		Mode: authmode.AuthModeJWT,
		TokenLocation: authscheme.TokenLocation{
			In:     authscheme.InHeader,
			Name:   "Authorization",
			Scheme: "Bearer",
		},
		Key: JWTKey{
			Algorithm: jose.RS256,
			Key:       goutils.ToPtr(goenvconf.NewEnvStringValue(publicKeyPEM)),
		},
		ClaimsConfig: JWTClaimsConfig{
			Locations: map[string]jmes.FieldMappingEntryConfig{
				"x-hasura-user-id": {
					Path: goutils.ToPtr("sub"),
				},
				"x-hasura-role": {
					Default: goutils.ToPtr(goenvconf.NewEnvAnyValue("admin")),
				},
			},
		},
	}

	authenticator, err := NewJWTAuthenticator(context.TODO(), []RelyAuthJWTConfig{config}, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	// Create a test JWT token with RSA
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	assert.NilError(t, err)

	claims := jwt.Claims{
		Subject:  "admin-456",
		Issuer:   "test-issuer",
		Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	assert.NilError(t, err)

	result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"authorization": "Bearer " + token,
		},
	})
	assert.NilError(t, err)
	assert.Equal(t, "test-jwt-rsa", result.ID)
	assert.Equal(t, "admin-456", result.SessionVariables["x-hasura-user-id"])
	assert.Equal(t, "admin", result.SessionVariables["x-hasura-role"])
}

func TestJWTAuthenticator_Authenticate_WithIssuerValidation(t *testing.T) {
	secret := "test-secret-key-at-least-32-bytes-long-for-hs256"
	expectedIssuer := "https://example.com"

	config := RelyAuthJWTConfig{
		Mode: authmode.AuthModeJWT,
		TokenLocation: authscheme.TokenLocation{
			In:     authscheme.InHeader,
			Name:   "Authorization",
			Scheme: "Bearer",
		},
		Issuer: expectedIssuer,
		Key: JWTKey{
			Algorithm: jose.HS256,
			Key:       goutils.ToPtr(goenvconf.NewEnvStringValue(secret)),
		},
		ClaimsConfig: JWTClaimsConfig{
			Locations: map[string]jmes.FieldMappingEntryConfig{
				"x-hasura-user-id": {
					Path: goutils.ToPtr("sub"),
				},
			},
		},
	}

	authenticator, err := NewJWTAuthenticator(context.TODO(), []RelyAuthJWTConfig{config}, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(secret)}, nil)
	assert.NilError(t, err)

	// Test with correct issuer
	claims := jwt.Claims{
		Subject:  "user-789",
		Issuer:   expectedIssuer,
		Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	assert.NilError(t, err)

	result, err := authenticator.Authenticate(context.Background(), &authmode.AuthenticateRequestData{
		Headers: map[string]string{
			"authorization": "Bearer " + token,
		},
	})
	assert.NilError(t, err)
	assert.Equal(t, "user-789", result.SessionVariables["x-hasura-user-id"])
}

func TestJWTAuthenticator_Equal(t *testing.T) {
	t.Run("equal_authenticators", func(t *testing.T) {
		config := RelyAuthJWTConfig{
			ID:   "test-jwt",
			Mode: authmode.AuthModeJWT,
			TokenLocation: authscheme.TokenLocation{
				In:   authscheme.InHeader,
				Name: "Authorization",
			},
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

		auth1, err := NewJWTAuthenticator(context.TODO(), []RelyAuthJWTConfig{config}, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer auth1.Close()

		auth2, err := NewJWTAuthenticator(context.TODO(), []RelyAuthJWTConfig{config}, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer auth2.Close()

		assert.Assert(t, auth1.Equal(*auth2))
	})

	t.Run("different_authenticators", func(t *testing.T) {
		config1 := RelyAuthJWTConfig{
			ID:   "test-jwt-1",
			Mode: authmode.AuthModeJWT,
			TokenLocation: authscheme.TokenLocation{
				In:   authscheme.InHeader,
				Name: "Authorization",
			},
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

		config2 := RelyAuthJWTConfig{
			ID:   "test-jwt-2",
			Mode: authmode.AuthModeJWT,
			TokenLocation: authscheme.TokenLocation{
				In:   authscheme.InHeader,
				Name: "Authorization",
			},
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

		auth1, err := NewJWTAuthenticator(context.TODO(), []RelyAuthJWTConfig{config1}, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer auth1.Close()

		auth2, err := NewJWTAuthenticator(context.TODO(), []RelyAuthJWTConfig{config2}, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer auth2.Close()

		assert.Assert(t, !auth1.Equal(*auth2))
	})

	t.Run("nil_keysets", func(t *testing.T) {
		auth1 := JWTAuthenticator{}
		auth2 := JWTAuthenticator{}

		assert.Assert(t, auth1.Equal(auth2))
	})
}

func TestJWTAuthenticator_Reload(t *testing.T) {
	config := RelyAuthJWTConfig{
		Mode: authmode.AuthModeJWT,
		TokenLocation: authscheme.TokenLocation{
			In:   authscheme.InHeader,
			Name: "Authorization",
		},
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

	authenticator, err := NewJWTAuthenticator(context.TODO(), []RelyAuthJWTConfig{config}, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	err = authenticator.Reload(context.TODO())
	assert.NilError(t, err)
}

func TestJWTAuthenticator_HasJWK(t *testing.T) {
	t.Run("with_static_key", func(t *testing.T) {
		config := RelyAuthJWTConfig{
			Mode: authmode.AuthModeJWT,
			TokenLocation: authscheme.TokenLocation{
				In:   authscheme.InHeader,
				Name: "Authorization",
			},
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

		authenticator, err := NewJWTAuthenticator(context.TODO(), []RelyAuthJWTConfig{config}, authmode.NewRelyAuthenticatorOptions())
		assert.NilError(t, err)
		defer authenticator.Close()

		assert.Assert(t, !authenticator.HasJWK())
	})
}

func TestJWTAuthenticator_Add(t *testing.T) {
	authenticator := &JWTAuthenticator{
		options: authmode.NewRelyAuthenticatorOptions(),
	}

	config := RelyAuthJWTConfig{
		ID:   "test-add",
		Mode: authmode.AuthModeJWT,
		TokenLocation: authscheme.TokenLocation{
			In:   authscheme.InHeader,
			Name: "Authorization",
		},
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

	err := authenticator.Add(context.TODO(), config)
	assert.NilError(t, err)
	assert.Assert(t, len(authenticator.keySets) > 0)
}

func TestJWTAuthenticator_MultipleConfigs(t *testing.T) {
	config1 := RelyAuthJWTConfig{
		ID:   "jwt-1",
		Mode: authmode.AuthModeJWT,
		TokenLocation: authscheme.TokenLocation{
			In:   authscheme.InHeader,
			Name: "Authorization",
		},
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

	config2 := RelyAuthJWTConfig{
		ID:   "jwt-2",
		Mode: authmode.AuthModeJWT,
		TokenLocation: authscheme.TokenLocation{
			In:   authscheme.InHeader,
			Name: "X-API-Key",
		},
		Key: JWTKey{
			Algorithm: jose.HS256,
			Key:       goutils.ToPtr(goenvconf.NewEnvStringValue("another-secret-key-for-testing-at-least-32-bytes")),
		},
		ClaimsConfig: JWTClaimsConfig{
			Locations: map[string]jmes.FieldMappingEntryConfig{
				"x-hasura-user-id": {Path: goutils.ToPtr("sub")},
			},
		},
	}

	authenticator, err := NewJWTAuthenticator(context.TODO(), []RelyAuthJWTConfig{config1, config2}, authmode.NewRelyAuthenticatorOptions())
	assert.NilError(t, err)
	defer authenticator.Close()

	assert.Assert(t, len(authenticator.keySets) == 2)
}
