package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/hasura/goenvconf"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
	"gotest.tools/v3/assert"
)

func TestReloadJWKS(t *testing.T) {
	defer CloseJWKS()

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

	keyset, err := NewJWTKeySet(context.TODO(), config, nil, authmode.RelyAuthenticatorOptions{})
	assert.NilError(t, err)
	defer keyset.Close()

	initialCallCount := callCount

	err = ReloadJWKS(context.TODO())
	assert.NilError(t, err)
	assert.Assert(t, callCount > initialCallCount)
}
