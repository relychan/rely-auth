package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/go-jose/go-jose/v4"
	"github.com/relychan/gohttpc"
	"github.com/relychan/goutils"
	"github.com/relychan/goutils/httpheader"
	"golang.org/x/sync/singleflight"
)

type jsonWebKeySet struct {
	Keys                []jose.JSONWebKey
	SignatureAlgorithms []jose.SignatureAlgorithm
}

// JWKS represents a JSON key set secret.
type JWKS struct {
	url      string
	inflight *singleflight.Group
	// A set of cached JSON Web keys.
	cachedKeys atomic.Pointer[jsonWebKeySet]
	// The HTTP client is used to fetch JSON web keys
	httpClient *gohttpc.Client
}

var _ SignatureVerifier = (*JWKS)(nil)

// GetSignatureAlgorithms get signature algorithms of the keyset.
func (j *JWKS) GetSignatureAlgorithms() []jose.SignatureAlgorithm {
	cachedKeys := j.cachedKeys.Load()
	if cachedKeys == nil {
		return []jose.SignatureAlgorithm{}
	}

	return cachedKeys.SignatureAlgorithms
}

// Equal checks if the target value is equal.
func (j *JWKS) Equal(target SignatureVerifier) bool {
	t, ok := target.(*JWKS)
	if !ok || t == nil {
		return false
	}

	return j.url == t.url
}

// VerifySignature verifies a JWT signature using cached and dynamically fetched JSON Web Keys (JWKS).
func (j *JWKS) VerifySignature(
	ctx context.Context,
	jws *jose.JSONWebSignature,
) ([]byte, error) {
	// We don't support JWTs signed with multiple signatures.
	keyID := ""

	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID

		break
	}

	keyset := j.cachedKeys.Load()
	if keyset != nil {
		for _, key := range keyset.Keys {
			if keyID == "" || key.KeyID == keyID {
				payload, err := jws.Verify(&key)
				if err == nil {
					return payload, nil
				}
			}
		}
	}

	// If the kid doesn't match, check for new keys from the remote. This is the
	// strategy recommended by the spec.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
	keys, err := j.keysFromRemoteInflight(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching keys %w", err)
	}

	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			payload, err := jws.Verify(&key)
			if err == nil {
				return payload, nil
			}
		}
	}

	return nil, ErrJWTVerificationFailed
}

// keysFromRemoteInflight syncs the key set from the remote set, records the values in the
// cache, and returns the key set.
func (j *JWKS) keysFromRemoteInflight(ctx context.Context) ([]jose.JSONWebKey, error) {
	result, err, _ := j.inflight.Do(j.url, func() (any, error) {
		return j.keysFromRemote(ctx)
	})
	if err != nil {
		return nil, err
	}

	keys, ok := result.([]jose.JSONWebKey)
	if !ok {
		return []jose.JSONWebKey{}, nil
	}

	return keys, nil
}

func (j *JWKS) keysFromRemote(ctx context.Context) ([]jose.JSONWebKey, error) {
	// Sync keys from the remote source.
	keys, updateErr := j.updateKeys(ctx)

	// If the keys were fetched successfully, update the cached keys and algorithms.
	if updateErr == nil {
		cachedKeys := &jsonWebKeySet{
			Keys:                keys,
			SignatureAlgorithms: getSignatureAlgorithmsFromJWKS(keys),
		}

		j.cachedKeys.Store(cachedKeys)
	}

	return keys, updateErr
}

func (j *JWKS) updateKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	req := j.httpClient.R(http.MethodGet, j.url)

	resp, err := req.Execute(ctx) //nolint:bodyclose
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrGetJWKsFailed, err.Error())
	}

	if resp.Body == nil {
		return nil, fmt.Errorf("%w: response body has no content", ErrGetJWKsFailed)
	}

	defer goutils.CatchWarnErrorFunc(resp.Body.Close)

	var keySet jose.JSONWebKeySet

	err = json.NewDecoder(resp.Body).Decode(&keySet)
	if err != nil {
		ct := resp.Header.Get(httpheader.ContentType)

		if strings.HasPrefix(ct, httpheader.ContentTypeJSON) {
			return nil, fmt.Errorf(
				"got Content-Type = application/json, but could not unmarshal as JSON: %w",
				err,
			)
		}

		return nil, fmt.Errorf("jwk: failed to decode keys: %w", err)
	}

	return keySet.Keys, nil
}
