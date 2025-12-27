package auth

import (
	"encoding/json"
	"fmt"

	"github.com/invopop/jsonschema"
	"github.com/relychan/rely-auth/auth/apikey"
	"github.com/relychan/rely-auth/auth/authmode"
	"github.com/relychan/rely-auth/auth/jwt"
	"github.com/relychan/rely-auth/auth/noauth"
	"github.com/relychan/rely-auth/auth/webhook"
	"go.yaml.in/yaml/v4"
)

// RelyAuthConfig is the data structure for authentication configurations.
type RelyAuthConfig struct {
	// Global settings of the auth config.
	Settings *authmode.RelyAuthSettings `json:"settings,omitempty" yaml:"settings,omitempty"`
	// List of authenticator configurations.
	Definitions []RelyAuthDefinition `json:"definitions" yaml:"definitions"`
}

// Validate checks if the configuration is valid.
func (rac RelyAuthConfig) Validate() error {
	var noAuth *RelyAuthDefinition

	for i, def := range rac.Definitions {
		err := def.Validate()
		if err != nil {
			return fmt.Errorf("invalid auth definition at %d: %w", i, err)
		}

		if def.GetMode() == authmode.AuthModeNoAuth {
			if noAuth != nil {
				return authmode.ErrOnlyOneNoAuthModeAllowed
			}

			noAuth = &def
		}
	}

	return nil
}

// RelyAuthDefinition wraps authentication configurations for an auth mode.
type RelyAuthDefinition struct {
	authmode.RelyAuthDefinitionInterface `yaml:",inline"`

	// Configurations for extra security rules .
	SecurityRules *authmode.RelyAuthSecurityRulesConfig `json:"securityRules,omitempty" yaml:"securityRules,omitempty"`
}

// NewRelyAuthDefinition creates a new [RelyAuthDefinition] instance.
func NewRelyAuthDefinition[T authmode.RelyAuthDefinitionInterface](inner T) RelyAuthDefinition {
	return RelyAuthDefinition{
		RelyAuthDefinitionInterface: inner,
	}
}

type rawRelyAuthDefinition struct {
	Mode          authmode.AuthMode                     `json:"mode" yaml:"mode"`
	SecurityRules *authmode.RelyAuthSecurityRulesConfig `json:"securityRules,omitempty" yaml:"securityRules,omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *RelyAuthDefinition) UnmarshalJSON(b []byte) error {
	var temp rawRelyAuthDefinition

	err := json.Unmarshal(b, &temp)
	if err != nil {
		return err
	}

	var config authmode.RelyAuthDefinitionInterface

	switch temp.Mode {
	case authmode.AuthModeNoAuth:
		config = new(noauth.RelyAuthNoAuthConfig)
	case authmode.AuthModeAPIKey:
		config = new(apikey.RelyAuthAPIKeyConfig)
	case authmode.AuthModeJWT:
		config = new(jwt.RelyAuthJWTConfig)
	case authmode.AuthModeWebhook:
		config = new(webhook.RelyAuthWebhookConfig)
	default:
		return fmt.Errorf("%w: %s", authmode.ErrUnsupportedAuthMode, temp.Mode)
	}

	err = json.Unmarshal(b, config)
	if err != nil {
		return err
	}

	err = config.Validate()
	if err != nil {
		return err
	}

	j.SecurityRules = temp.SecurityRules
	j.RelyAuthDefinitionInterface = config

	return nil
}

// UnmarshalYAML implements the custom behavior for the yaml.Unmarshaler interface.
func (j *RelyAuthDefinition) UnmarshalYAML(value *yaml.Node) error {
	var temp rawRelyAuthDefinition

	err := value.Decode(&temp)
	if err != nil {
		return err
	}

	var config authmode.RelyAuthDefinitionInterface

	switch temp.Mode {
	case authmode.AuthModeNoAuth:
		config = new(noauth.RelyAuthNoAuthConfig)
	case authmode.AuthModeAPIKey:
		config = new(apikey.RelyAuthAPIKeyConfig)
	case authmode.AuthModeJWT:
		config = new(jwt.RelyAuthJWTConfig)
	case authmode.AuthModeWebhook:
		config = new(webhook.RelyAuthWebhookConfig)
	default:
		return fmt.Errorf("%w: %s", authmode.ErrUnsupportedAuthMode, temp.Mode)
	}

	err = value.Decode(config)
	if err != nil {
		return err
	}

	err = config.Validate()
	if err != nil {
		return err
	}

	j.SecurityRules = temp.SecurityRules
	j.RelyAuthDefinitionInterface = config

	return nil
}

// Validate if the current instance is valid.
func (j RelyAuthDefinition) Validate() error {
	if j.RelyAuthDefinitionInterface == nil {
		return authmode.ErrAuthConfigRequired
	}

	return j.RelyAuthDefinitionInterface.Validate()
}

// JSONSchema defines a custom definition for JSON schema.
func (RelyAuthDefinition) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		OneOf: []*jsonschema.Schema{
			{
				Ref: "#/$defs/RelyAuthAPIKeyConfig",
			},
			{
				Ref: "#/$defs/RelyAuthJWTConfig",
			},
			{
				Ref: "#/$defs/RelyAuthNoAuthConfig",
			},
			{
				Ref: "#/$defs/RelyAuthWebhookConfig",
			},
		},
	}
}
