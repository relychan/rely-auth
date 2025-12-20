package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hasura/goenvconf"
	"github.com/jmespath-community/go-jmespath"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
)

// JWTKeySet is a verifier that validates JWT against a static set of HMAC or public keys.
type JWTKeySet struct {
	config *RelyAuthJWTConfig
	// cached locations after resolving environment variables
	locations         map[string]jmes.FieldMappingEntry
	signatureVerifier SignatureVerifier
}

// NewJWTKeySet creates a new JWT key set from the configuration.
func NewJWTKeySet(
	ctx context.Context,
	config *RelyAuthJWTConfig,
	options authmode.RelyAuthenticatorOptions,
) (*JWTKeySet, error) {
	result := JWTKeySet{
		config: config,
	}

	err := result.init(ctx, options)

	return &result, err
}

// Equal checks if the target value is equal.
func (j *JWTKeySet) Equal(target *JWTKeySet) bool {
	if !goutils.EqualPtr(j.config, target.config) {
		return false
	}

	return j.signatureVerifier != nil && target.signatureVerifier != nil &&
		j.signatureVerifier.Equal(target.signatureVerifier)
}

// GetConfig get config of the current keyset.
func (j *JWTKeySet) GetConfig() *RelyAuthJWTConfig {
	return j.config
}

// Close handles the resources cleaning.
func (*JWTKeySet) Close() error {
	return nil
}

// GetSignatureAlgorithms get signature algorithms of the keyset.
func (j *JWTKeySet) GetSignatureAlgorithms() []jose.SignatureAlgorithm {
	algorithms := j.signatureVerifier.GetSignatureAlgorithms()
	if len(algorithms) > 0 {
		return algorithms
	}

	return GetSupportedSignatureAlgorithms()
}

// VerifySignature verifies a JWT signature using the configured signature verifier.
func (j *JWTKeySet) VerifySignature(
	ctx context.Context,
	sig *jose.JSONWebSignature,
) ([]byte, error) {
	return j.signatureVerifier.VerifySignature(ctx, sig)
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

	return evalHasuraSessionVariables(result)
}

func (j *JWTKeySet) init(ctx context.Context, options authmode.RelyAuthenticatorOptions) error {
	getEnvFunc := options.GetEnvFunc(ctx)
	// load locations
	locations, err := jmes.EvaluateObjectFieldMappingEntries(
		j.config.ClaimsConfig.Locations,
		getEnvFunc,
	)
	if err != nil {
		return fmt.Errorf("failed to get location value: %w", err)
	}

	j.locations = locations

	if j.config.Key.Key != nil {
		return j.initJWTKey(getEnvFunc)
	}

	if j.config.Key.JWKFromURL == nil {
		return ErrJWTAuthKeyRequired
	}

	jwksURL, err := j.config.Key.JWKFromURL.GetCustom(getEnvFunc)
	if err != nil {
		return err
	}

	j.signatureVerifier, err = RegisterJWKS(ctx, jwksURL, options.HTTPClient)

	return err
}

func (j *JWTKeySet) initJWTKey(getEnvFunc goenvconf.GetEnvFunc) error {
	rawKey, err := j.config.Key.Key.GetCustom(getEnvFunc)
	if err != nil {
		return err
	}

	j.signatureVerifier, err = NewStaticKey([]byte(rawKey), j.config.Key.Algorithm)

	return err
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
