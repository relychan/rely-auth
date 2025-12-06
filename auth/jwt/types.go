package jwt

import (
	"errors"
	"fmt"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/invopop/jsonschema"
	"github.com/relychan/goutils"
)

var (
	// ErrJWTAuthKeyRequired occurs when either JWT key or JWK URL is empty.
	ErrJWTAuthKeyRequired = errors.New("require either JWT key or JWK URL")
	// ErrJWTClaimsConfigEmpty occurs when the JWT claims config is empty.
	ErrJWTClaimsConfigEmpty = errors.New(
		"invalid claims config. Require either namespace or locations",
	)
	// ErrJWTClaimsConfigInvalidLocation occurs when the location config of JWT claims is invalid.
	ErrJWTClaimsConfigInvalidLocation = errors.New("invalid claims location")
	// ErrJWTClaimsNull occurs when the JWT claims value is null.
	ErrJWTClaimsNull = errors.New("jwt claims data is null")
	// ErrJWTClaimsMalformedStringifyJSON occurs when the JWT claims value is not a JSON string.
	ErrJWTClaimsMalformedStringifyJSON = errors.New(
		"invalid jwt claims data: malformed stringify json",
	)
	// ErrJWTClaimsMalformedJSON occurs when the JWT claims value is not a JSON object.
	ErrJWTClaimsMalformedJSON = errors.New("invalid jwt claims data: malformed json object")
	// ErrInvalidJWTClaimsFormat occurs when the JWT claims format is invalid.
	ErrInvalidJWTClaimsFormat = fmt.Errorf(
		"invalid JWTClaimsFormat. Expected one of %v",
		GetSupportedJWTClaimsFormats(),
	)
	// ErrInvalidSignatureAlgorithm occurs when the JWT signature algorithm enum is invalid.
	ErrInvalidSignatureAlgorithm = fmt.Errorf(
		"invalid SignatureAlgorithm. Expected one of %v",
		GetSupportedSignatureAlgorithms(),
	)
	// ErrGetJWKsFailed occurs when failed to get JSON web keys from the remote URL.
	ErrGetJWKsFailed = errors.New("jwk: get keys failed")
	// ErrJWTVerificationFailed occurs when failed to verify the JWT auth token.
	ErrJWTVerificationFailed = errors.New("failed to verify jwt token signature")
	// ErrInvalidJWTKey occurs when the JWT key is invalid.
	ErrInvalidJWTKey = errors.New("invalid JWT key")
)

// JWTClaimsFormat is the format in which JWT claims will be present.
type JWTClaimsFormat string

const (
	// JWTClaimsFormatJSON the claims will be in the JSON format.
	JWTClaimsFormatJSON JWTClaimsFormat = "Json"
	// JWTClaimsFormatStringifiedJSON the claims will be in the Stringified JSON format.
	JWTClaimsFormatStringifiedJSON JWTClaimsFormat = "StringifiedJson"
)

var enumValueJWTClaimsFormats = []JWTClaimsFormat{
	JWTClaimsFormatJSON,
	JWTClaimsFormatStringifiedJSON,
}

// Validate checks if the value is valid.
func (j JWTClaimsFormat) Validate() error {
	if !slices.Contains(enumValueJWTClaimsFormats, j) {
		return fmt.Errorf(
			"%w, got <%s>",
			ErrInvalidJWTClaimsFormat,
			j,
		)
	}

	return nil
}

// JSONSchema defines a custom definition for JSON schema.
func (JWTClaimsFormat) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Description: "The format in which JWT claims will be present",
		Enum:        goutils.ToAnySlice(GetSupportedJWTClaimsFormats()),
	}
}

// GetSupportedJWTClaimsFormats get the list of supported JWT claims formats.
func GetSupportedJWTClaimsFormats() []JWTClaimsFormat {
	return enumValueJWTClaimsFormats
}

// ParseJWTClaimsFormat parses a JWTClaimsFormat from string.
func ParseJWTClaimsFormat(value string) (JWTClaimsFormat, error) {
	result := JWTClaimsFormat(value)

	return result, result.Validate()
}

var enumValueSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.EdDSA,
	jose.HS256,
	jose.HS384,
	jose.HS512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
	jose.RS256,
	jose.RS384,
	jose.RS512,
}

// ParseSignatureAlgorithm parses a SignatureAlgorithm from string.
func ParseSignatureAlgorithm(value string) (jose.SignatureAlgorithm, error) {
	result := jose.SignatureAlgorithm(value)
	if !slices.Contains(enumValueSignatureAlgorithms, result) {
		return result, fmt.Errorf(
			"%w, got <%s>",
			ErrInvalidSignatureAlgorithm,
			value,
		)
	}

	return result, nil
}

// GetSupportedSignatureAlgorithms get the list of supported signature algorithms for JSON Web Token.
func GetSupportedSignatureAlgorithms() []jose.SignatureAlgorithm {
	return enumValueSignatureAlgorithms
}
