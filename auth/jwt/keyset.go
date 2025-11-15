package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime"
	"net/http"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jmespath-community/go-jmespath"
	"github.com/relychan/gohttps"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/goutils"
	"golang.org/x/sync/singleflight"
	"resty.dev/v3"
)

// JWTKeySet is a verifier that validates JWT against a static set of HMAC or public keys.
type JWTKeySet struct {
	config *RelyAuthJWTConfig
	// Static HMAC key
	hmacKey []byte
	// PublicKeys used to verify the JWT. Supported types are *rsa.PublicKey and
	// *ecdsa.PublicKey.
	publicKey crypto.PublicKey

	// current JWKs URL
	jwksURL string

	// inflight suppresses parallel execution of updateKeys and allows
	// multiple goroutines to wait for its result.
	inflight *singleflight.Group

	// A set of cached JSON Web keys.
	cachedKeys []jose.JSONWebKey

	// cached locations after resolving environment variables
	locations map[string]jmes.FieldMappingEntry

	httpClient *resty.Client

	mu sync.RWMutex
}

// NewJWTKeySet creates a new JWT key set from the configuration.
func NewJWTKeySet(config *RelyAuthJWTConfig, httpClient *resty.Client) (*JWTKeySet, error) {
	if httpClient == nil {
		httpClient = resty.New()
	}

	result := JWTKeySet{
		config:     config,
		httpClient: httpClient,
		inflight:   &singleflight.Group{},
	}

	err := result.doReload(context.Background())

	return &result, err
}

// GetConfig get config of the current keyset.
func (j *JWTKeySet) GetConfig() *RelyAuthJWTConfig {
	return j.config
}

// Close handles the resources cleaning.
func (j *JWTKeySet) Close() error {
	if j.httpClient != nil {
		return j.httpClient.Close()
	}

	return nil
}

// GetSignatureAlgorithms get signature algorithms of the keyset.
func (j *JWTKeySet) GetSignatureAlgorithms() []jose.SignatureAlgorithm {
	result := make([]jose.SignatureAlgorithm, 0, len(j.cachedKeys))

	for _, key := range j.cachedKeys {
		alg := jose.SignatureAlgorithm(key.Algorithm)

		if key.Algorithm != "" && !slices.Contains(result, alg) {
			result = append(result, alg)
		}
	}

	if len(result) > 0 {
		return slices.Compact(result)
	}

	if j.config.Key.Algorithm != "" {
		return []jose.SignatureAlgorithm{j.config.Key.Algorithm}
	}

	return GetSupportedSignatureAlgorithms()
}

// VerifySignature compares the json web token against a static set of JWT secret keys.
func (j *JWTKeySet) VerifySignature(
	ctx context.Context,
	sig *jose.JSONWebSignature,
) ([]byte, error) {
	switch {
	case len(j.cachedKeys) > 0:
		return j.verifyJWKs(ctx, sig)
	case j.publicKey != nil:
		return sig.Verify(j.publicKey)
	case len(j.hmacKey) > 0:
		return sig.Verify(j.hmacKey)
	default:
		return nil, gohttps.NewUnauthorizedError()
	}
}

// ValidateClaims checks claims in a token against expected values.
func (j *JWTKeySet) ValidateClaims(claims *jwt.Claims) error {
	expectedClaims := jwt.Expected{
		Issuer:      j.config.Issuer,
		AnyAudience: j.config.Audience,
	}

	leeway := jwt.DefaultLeeway

	if j.config.AllowedSkew > 0 {
		leeway = time.Duration(j.config.AllowedSkew) * time.Second
	}

	return claims.ValidateWithLeeway(expectedClaims, leeway)
}

// TransformClaims transform JWT claims to expected session variables.
func (j *JWTKeySet) TransformClaims(rawBytes []byte) (map[string]any, error) {
	if len(rawBytes) == 0 {
		return nil, ErrJWTClaimsNull
	}

	var rawClaims map[string]any

	err := json.Unmarshal(rawBytes, &rawClaims)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrJWTClaimsMalformedJSON, err.Error())
	}

	result, err := j.getClaimsFromNamespace(rawClaims)
	if err != nil {
		return nil, err
	}

	for key, loc := range j.locations {
		claimValue, err := loc.Evaluate(rawClaims)
		if err != nil || claimValue == nil {
			result[key] = loc.Default
		} else {
			result[key] = claimValue
		}
	}

	return result, nil
}

// Reload credentials of the authenticator.
func (j *JWTKeySet) Reload(ctx context.Context) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	return j.doReload(ctx)
}

func (j *JWTKeySet) doReload(ctx context.Context) error {
	// load locations
	locations, err := jmes.EvaluateObjectFieldMappingEntries(j.config.ClaimsConfig.Locations)
	if err != nil {
		return fmt.Errorf("failed to get location value: %w", err)
	}

	j.locations = locations

	if j.config.Key.Key != nil {
		return j.reloadJWTKey()
	}

	if j.config.Key.JWKFromURL == nil {
		return ErrJWTAuthKeyRequired
	}

	jwksURL, err := j.config.Key.JWKFromURL.Get()
	if err != nil {
		return err
	}

	// update keys only if JWKs URL is changed.
	if j.jwksURL != jwksURL {
		j.jwksURL = jwksURL

		_, err := j.updateKeys(ctx)

		return err
	}

	return nil
}

func (j *JWTKeySet) reloadJWTKey() error {
	rawKey, err := j.config.Key.Key.Get()
	if err != nil {
		return err
	}

	if rawKey == "" {
		return ErrJWTAuthKeyRequired
	}

	switch j.config.Key.Algorithm {
	case jose.HS256, jose.HS384, jose.HS512:
		j.hmacKey = []byte(rawKey)
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		spkiBlock, _ := pem.Decode([]byte(rawKey))

		pubInterface, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
		if err != nil {
			return err
		}

		rsaPubKey, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: The public key is not an RSA key", ErrInvalidJWTKey)
		}

		j.publicKey = rsaPubKey
	case jose.ES256, jose.ES384, jose.ES512:
		spkiBlock, _ := pem.Decode([]byte(rawKey))

		pubInterface, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
		if err != nil {
			return err
		}

		pubKey, ok := pubInterface.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: The public key is not an ECDSA key", ErrInvalidJWTKey)
		}

		j.publicKey = pubKey
	case jose.EdDSA:
		spkiBlock, _ := pem.Decode([]byte(rawKey))

		pubInterface, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
		if err != nil {
			return err
		}

		pubKey, ok := pubInterface.(*ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: The public key is not an Ed25519 key", ErrInvalidJWTKey)
		}

		j.publicKey = pubKey
	default:
		return fmt.Errorf("%w: %s", jose.ErrUnsupportedAlgorithm, j.config.Key.Algorithm)
	}

	return nil
}

func (j *JWTKeySet) getClaimsFromNamespace(rawClaims map[string]any) (map[string]any, error) {
	if j.config.ClaimsConfig.Namespace == nil || j.config.ClaimsConfig.Namespace.Location == "" {
		return map[string]any{}, nil
	}

	rawNamespace, err := jmespath.Search(j.config.ClaimsConfig.Namespace.Location, rawClaims)
	if err != nil || rawNamespace == nil {
		return map[string]any{}, err
	}

	if j.config.ClaimsConfig.Namespace.ClaimsFormat == JWTClaimsFormatStringifiedJSON {
		rawClaimsString, ok := rawNamespace.(string)
		if !ok {
			return nil, ErrJWTClaimsMalformedStringifyJSON
		}

		var rawJSONValue map[string]any

		err := json.Unmarshal([]byte(rawClaimsString), &rawJSONValue)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: %s",
				ErrJWTClaimsMalformedStringifyJSON,
				err.Error(),
			)
		}

		return rawJSONValue, nil
	}

	rawJSONValue, ok := rawNamespace.(map[string]any)
	if !ok {
		return nil, fmt.Errorf(
			"%w. Expected a JSON object, got: %s",
			ErrJWTClaimsMalformedJSON,
			reflect.TypeOf(rawNamespace),
		)
	}

	return rawJSONValue, nil
}

func (j *JWTKeySet) verifyJWKs(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	// We don't support JWTs signed with multiple signatures.
	keyID := ""

	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID

		break
	}

	keys := j.keysFromCache()

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
	keys, err := j.keysFromRemote(ctx)
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

func (j *JWTKeySet) keysFromCache() []jose.JSONWebKey {
	j.mu.RLock()
	defer j.mu.RUnlock()

	return j.cachedKeys
}

// keysFromRemote syncs the key set from the remote set, records the values in the
// cache, and returns the key set.
func (j *JWTKeySet) keysFromRemote(ctx context.Context) ([]jose.JSONWebKey, error) {
	result, err, _ := j.inflight.Do(j.jwksURL, func() (any, error) {
		// Sync keys and finish inflight when that's done.
		keys, updateErr := j.updateKeys(ctx)

		// Lock to update the keys and indicate that there is no longer an
		// inflight request.
		j.mu.Lock()
		defer j.mu.Unlock()

		if updateErr == nil {
			j.cachedKeys = keys
		}

		return j.cachedKeys, updateErr
	})
	if err != nil {
		return nil, err
	}

	keys, ok := result.([]jose.JSONWebKey)
	if !ok {
		return j.keysFromCache(), nil
	}

	return keys, nil
}

func (j *JWTKeySet) updateKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	req := j.httpClient.R().SetContext(ctx)

	resp, err := req.Execute(http.MethodGet, j.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrGetJWKsFailed, err.Error())
	}

	defer goutils.CatchWarnErrorFunc(resp.Body.Close)

	if resp.StatusCode() != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("unable to read response body: %w", err)
		}

		return nil, fmt.Errorf("%w: %s %s", ErrGetJWKsFailed, resp.Status(), body)
	}

	var keySet jose.JSONWebKeySet

	err = json.NewDecoder(resp.Body).Decode(&keySet)
	if err != nil {
		ct := resp.Header().Get("Content-Type")

		mediaType, _, parseErr := mime.ParseMediaType(ct)
		if parseErr == nil && mediaType == "application/json" {
			return nil, fmt.Errorf(
				"got Content-Type = application/json, but could not unmarshal as JSON: %w",
				err,
			)
		}

		return nil, fmt.Errorf("jwk: failed to decode keys: %w", err)
	}

	return keySet.Keys, nil
}
