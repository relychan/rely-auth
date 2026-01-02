package jwt

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/hasura/goenvconf"
	"github.com/invopop/jsonschema"
	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

// RelyAuthJWTConfig holds configurations to which the incoming JWT will be verified and decoded to extract the session variable claims.
type RelyAuthJWTConfig struct {
	// Unique identity of the auth config.
	// If not set, ID will be the index of the array.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`
	// Authentication mode which is always jwt.
	Mode authmode.AuthMode `json:"mode" jsonschema:"enum=jwt" yaml:"mode"`
	// Brief description of the auth config.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Validation to check that the aud field is a member of the audience received, otherwise will throw error.
	// Required if there are many JWT auth configurations.
	Audience []string `json:"audience,omitempty" yaml:"audience,omitempty"`
	// Validation to check that the iss field is a member of the iss received, otherwise will throw error.
	// Required if there are many JWT auth configurations.
	Issuer string `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	// The allowed leeway (in seconds) to the exp validation to account for clock skew.
	AllowedSkew int `json:"allowedSkew,omitempty" yaml:"allowedSkew,omitempty"`
	// Source of the JWT authentication token.
	TokenLocation authscheme.TokenLocation `json:"tokenLocation" yaml:"tokenLocation"`
	// Information of the JWT key to verify the token.
	Key JWTKey `json:"key" yaml:"key"`
	// Configuration to describe how and where the engine should look for the claims within the decoded token.
	// You can vary the format and location of the claims.
	ClaimsConfig JWTClaimsConfig `json:"claimsConfig" yaml:"claimsConfig"`
}

var _ authmode.RelyAuthModeInterface = (*RelyAuthJWTConfig)(nil)

// NewRelyAuthJWTConfig creates a new JWTAuthDefinition instance.
func NewRelyAuthJWTConfig(key JWTKey, tokenLocation authscheme.TokenLocation) *RelyAuthJWTConfig {
	return &RelyAuthJWTConfig{
		Key:           key,
		TokenLocation: tokenLocation,
	}
}

// GetMode returns the auth mode of the current config.
func (RelyAuthJWTConfig) GetMode() authmode.AuthMode {
	return authmode.AuthModeJWT
}

// IsZero if the current instance is empty.
func (j RelyAuthJWTConfig) IsZero() bool {
	return j.ID == "" &&
		j.Mode == "" &&
		j.Description == "" &&
		len(j.Audience) == 0 &&
		j.Issuer == "" &&
		j.AllowedSkew == 0 &&
		j.TokenLocation.IsZero() &&
		j.Key.IsZero() &&
		j.ClaimsConfig.IsZero()
}

// Equal checks if the target value is equal.
func (j RelyAuthJWTConfig) Equal(target RelyAuthJWTConfig) bool {
	return j.ID == target.ID &&
		j.Mode == target.Mode &&
		goutils.EqualSliceSorted(j.Audience, target.Audience) &&
		j.Issuer == target.Issuer &&
		j.AllowedSkew == target.AllowedSkew &&
		j.TokenLocation.Equal(target.TokenLocation) &&
		j.Key.Equal(target.Key) &&
		j.ClaimsConfig.Equal(target.ClaimsConfig)
}

// Validate if the current instance is valid.
func (j RelyAuthJWTConfig) Validate() error {
	err := j.ClaimsConfig.Validate()
	if err != nil {
		return err
	}

	err = j.TokenLocation.Validate()
	if err != nil {
		return err
	}

	err = j.Key.Validate()
	if err != nil {
		return err
	}

	return nil
}

// JWTClaimsConfig represents the claims config. Either specified via claims mappings or namespace.
type JWTClaimsConfig struct {
	// Used when all of JWT claims are present in a single object within the decoded JWT.
	Namespace *JWTClaimsNamespace `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	// Can be used when JWT claims are not all present in the single object,
	// but individual claims are provided a JSON pointer within the decoded JWT and optionally a default value.
	Locations map[string]jmes.FieldMappingEntryConfig `json:"locations,omitempty" yaml:"locations,omitempty"`
}

// IsZero if the current instance is empty.
func (j JWTClaimsConfig) IsZero() bool {
	return (j.Namespace == nil || j.Namespace.IsZero()) &&
		len(j.Locations) == 0
}

// Equal checks if the target value is equal.
func (j JWTClaimsConfig) Equal(target JWTClaimsConfig) bool {
	return goutils.EqualPtr(j.Namespace, target.Namespace) &&
		goutils.EqualMap(j.Locations, target.Locations, true)
}

// Validate if the current instance is valid.
func (j JWTClaimsConfig) Validate() error {
	if j.Namespace == nil && len(j.Locations) == 0 {
		return ErrJWTClaimsConfigEmpty
	}

	if j.Namespace != nil {
		err := j.Namespace.ClaimsFormat.Validate()
		if err != nil {
			return err
		}
	}

	return nil
}

// JWTKey holds the information of the JWT key to verify the token.
type JWTKey struct {
	// Algorithm specifies the cryptographic signing algorithm which is used to sign the JWTs.
	// This is required only if you are using the key property in the config.
	Algorithm jose.SignatureAlgorithm `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	// An URL where a provider publishes their JWKs (JSON Web Keys - which are used for signing the JWTs).
	// The URL must publish the JWKs in the standard format as described in the RFC 7517 specification.
	// This is optional as you have the alternative of also providing the key (certificate, PEM-encoded public key) as a string - in the key field along with the type.
	JWKFromURL *goenvconf.EnvString `json:"jwkFromUrl,omitempty" yaml:"jwkFromUrl,omitempty"`
	// Inline value of the key to use for decoding the JWT.
	Key *goenvconf.EnvString `json:"key,omitempty" yaml:"key,omitempty"`
}

// IsZero if the current instance is empty.
func (j JWTKey) IsZero() bool {
	return j.Algorithm == "" &&
		(j.JWKFromURL == nil || j.JWKFromURL.IsZero()) &&
		(j.Key == nil || j.Key.IsZero())
}

// Equal checks if the target value is equal.
func (j JWTKey) Equal(target JWTKey) bool {
	return j.Algorithm == target.Algorithm &&
		goutils.EqualPtr(j.JWKFromURL, target.JWKFromURL) &&
		goutils.EqualPtr(j.Key, target.Key)
}

// JSONSchema defines a custom definition for JSON schema.
func (JWTKey) JSONSchema() *jsonschema.Schema {
	envStringRef := "#/$defs/EnvString"
	algorithmProp := &jsonschema.Schema{
		Description: "Algorithm to be used for verifying the signature",
		Ref:         "#/$defs/JWTSignatureAlgorithm",
	}

	keyProps := orderedmap.New[string, *jsonschema.Schema]()
	keyProps.Set("algorithm", algorithmProp)
	keyProps.Set("key", &jsonschema.Schema{
		Description: "Inline value of the key to use for decoding the JWT",
		Ref:         envStringRef,
	})

	jwkFromURLProps := orderedmap.New[string, *jsonschema.Schema]()
	jwkFromURLProps.Set("algorithm", algorithmProp)
	jwkFromURLProps.Set("jwkFromUrl", &jsonschema.Schema{
		Description: "A URL where a provider publishes their JWKs (JSON Web Keys - which are used for signing the JWTs). The URL must publish the JWKs in the standard format as described in the RFC 7517 specification.", //nolint:lll
		Ref:         envStringRef,
	})

	return &jsonschema.Schema{
		OneOf: []*jsonschema.Schema{
			{
				Type:        "object",
				Title:       "JWTFixedKeyConfig",
				Required:    []string{"algorithm", "key"},
				Description: "Configurations for an inline JWT key secret",
				Properties:  keyProps,
			},
			{
				Type:        "object",
				Title:       "JWTRemoteKeyConfig",
				Properties:  jwkFromURLProps,
				Description: "Configurations for a remote URL where publishes JSON Web Keys",
				Required:    []string{"jwkFromUrl"},
			},
		},
	}
}

// Validate if the current instance is valid.
func (j JWTKey) Validate() error {
	if j.Key != nil && !j.Key.IsZero() {
		_, err := ParseSignatureAlgorithm(string(j.Algorithm))

		return err
	}

	if j.JWKFromURL == nil || j.JWKFromURL.IsZero() {
		return ErrJWTAuthKeyRequired
	}

	if j.Algorithm != "" {
		_, err := ParseSignatureAlgorithm(string(j.Algorithm))

		return err
	}

	return nil
}

// JWTClaimsNamespace is used when all of JWT claims are present in a single object within the decoded JWT.
type JWTClaimsNamespace struct {
	// Path to lookup the Hasura claims within the decoded claims.
	Location string `json:"location" yaml:"location"`
	// Format in which the Hasura claims will be present.
	ClaimsFormat JWTClaimsFormat `json:"claimsFormat" jsonschema:"enum=Json,enum=StringifiedJson" yaml:"claimsFormat"`
}

// IsZero if the current instance is empty.
func (j JWTClaimsNamespace) IsZero() bool {
	return j.Location == "" && j.ClaimsFormat == ""
}

// Equal checks if the target value is equal.
func (j JWTClaimsNamespace) Equal(target JWTClaimsNamespace) bool {
	return j.Location == target.Location &&
		j.ClaimsFormat == target.ClaimsFormat
}

// Validate if the current instance is valid.
func (j JWTClaimsNamespace) Validate() error {
	_, err := ParseJWTClaimsFormat(string(j.ClaimsFormat))

	return err
}
