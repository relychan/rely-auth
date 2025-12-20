package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/relychan/gohttpc"
	"github.com/relychan/goutils"
	"github.com/relychan/goutils/httpheader"
	"golang.org/x/sync/singleflight"
)

// JWKStore represents a global JWT store structure.
type JWKStore struct {
	// inflight suppresses parallel execution of updateKeys and allows
	// multiple goroutines to wait for its result.
	inflight *singleflight.Group
	// Set of JWKS map.
	jwks map[string]*JWKS
	// The default http client to fetch JWKs.
	httpClient *gohttpc.Client
}

var globalJWKStore = JWKStore{
	inflight: &singleflight.Group{},
	jwks:     map[string]*JWKS{},
}

// JWKS represents a JSON key set secret.
type JWKS struct {
	url      string
	inflight *singleflight.Group
	// A set of cached JSON Web keys.
	cachedKeys          []jose.JSONWebKey
	signatureAlgorithms []jose.SignatureAlgorithm
	// The HTTP client is used to fetch JSON web keys
	httpClient *gohttpc.Client
}

var _ SignatureVerifier = (*JWKS)(nil)

// GetSignatureAlgorithms get signature algorithms of the keyset.
func (j *JWKS) GetSignatureAlgorithms() []jose.SignatureAlgorithm {
	return j.signatureAlgorithms
}

// Equal checks if the target value is equal.
func (j *JWKS) Equal(target SignatureVerifier) bool {
	t, ok := target.(*JWKS)
	if !ok || t == nil {
		return false
	}

	return j.url == t.url
}

// VerifySignature compares the json web token against a static set of JWT secret key.
func (j *JWKS) VerifySignature(
	ctx context.Context,
	sig *jose.JSONWebSignature,
) ([]byte, error) {
	return j.verifyJWKs(ctx, sig)
}

func (j *JWKS) verifyJWKs(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	// We don't support JWTs signed with multiple signatures.
	keyID := ""

	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID

		break
	}

	keys := j.cachedKeys

	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			payload, err := jws.Verify(&key)
			if err == nil {
				return payload, nil
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
	// Sync keys and finish inflight when that's done.
	keys, updateErr := j.updateKeys(ctx)

	// Lock to update the keys and indicate that there is no longer an
	// inflight request.
	if updateErr == nil {
		j.cachedKeys = keys
		j.signatureAlgorithms = getSignatureAlgorithmsFromJWKS(keys)
	}

	return j.cachedKeys, updateErr
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

func getSignatureAlgorithmsFromJWKS(keys []jose.JSONWebKey) []jose.SignatureAlgorithm {
	results := make([]jose.SignatureAlgorithm, 0, len(keys))

	for _, key := range keys {
		if key.Algorithm == "" {
			continue
		}

		alg := jose.SignatureAlgorithm(key.Algorithm)
		results = append(results, alg)
	}

	if len(results) == 0 {
		return []jose.SignatureAlgorithm{}
	}

	slices.Sort(results)

	return slices.Compact(results)
}

// RegisterJWKS registers a JWK secret key to the global store.
func RegisterJWKS(ctx context.Context, jwksURL string, httpClient *gohttpc.Client) (*JWKS, error) {
	trimmedURL := strings.TrimRight(jwksURL, "/")
	if trimmedURL == "" {
		return nil, ErrJWKsURLRequired
	}

	keyset, err, _ := globalJWKStore.inflight.Do(trimmedURL, func() (any, error) {
		jwk, ok := globalJWKStore.jwks[trimmedURL]
		if ok {
			return jwk, nil
		}

		if httpClient == nil {
			if globalJWKStore.httpClient == nil {
				globalJWKStore.httpClient = gohttpc.NewClient()
			}

			httpClient = globalJWKStore.httpClient
		}

		jwk = &JWKS{
			url:        trimmedURL,
			httpClient: httpClient,
			inflight:   globalJWKStore.inflight,
		}

		// fetch JSON web key to validate if the JWK URL is valid.
		_, err := jwk.keysFromRemote(ctx)
		if err != nil {
			return nil, err
		}

		globalJWKStore.jwks[trimmedURL] = jwk

		return jwk, nil
	})
	if err != nil {
		return nil, err
	}

	result, ok := keyset.(*JWKS)
	if !ok {
		return nil, ErrGetJWKsFailed
	}

	return result, nil
}

// GetJWKSCount gets the current number of JWKs secret keys from the global store.
func GetJWKSCount() int {
	return len(globalJWKStore.jwks)
}

// ReloadJWKS reload JWK secret keys from the global store.
func ReloadJWKS(ctx context.Context) error {
	errs := []error{}

	for _, jwk := range globalJWKStore.jwks {
		_, err := jwk.keysFromRemoteInflight(ctx)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
