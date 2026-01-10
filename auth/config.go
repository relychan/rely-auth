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
	// Version of the authentication config.
	Version string `json:"version" yaml:"version" jsonschema:"enum=v1"`
	// Kind of the resource which is always RelyAuth.
	Kind string `json:"kind" yaml:"kind" jsonschema:"enum=RelyAuth"`
	// List of authenticator configurations.
	Definition RelyAuthDefinition `json:"definition" yaml:"definition"`
}

// Validate checks if the configuration is valid.
func (rac RelyAuthConfig) Validate() error {
	var noAuth *RelyAuthMode

	for i, def := range rac.Definition.Modes {
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

// RelyAuthDefinition defines authentication modes and settings.
type RelyAuthDefinition struct {
	// Global settings of the auth config.
	Settings *authmode.RelyAuthSettings `json:"settings,omitempty" yaml:"settings,omitempty"`
	// List of authenticator modes.
	Modes []RelyAuthMode `json:"modes" yaml:"modes"`
}

// RelyAuthMode wraps authentication configurations for an auth mode.
type RelyAuthMode struct {
	authmode.RelyAuthModeInterface `yaml:",inline"`

	// Configurations for extra security rules.
	SecurityRules *authmode.RelyAuthSecurityRulesConfig `json:"securityRules,omitempty" yaml:"securityRules,omitempty"`
}

// NewRelyAuthMode creates a new [RelyAuthMode] instance.
func NewRelyAuthMode[T authmode.RelyAuthModeInterface](inner T) RelyAuthMode {
	return RelyAuthMode{
		RelyAuthModeInterface: inner,
	}
}

type rawRelyAuthMode struct {
	Mode          authmode.AuthMode                     `json:"mode" yaml:"mode"`
	SecurityRules *authmode.RelyAuthSecurityRulesConfig `json:"securityRules,omitempty" yaml:"securityRules,omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *RelyAuthMode) UnmarshalJSON(b []byte) error {
	var temp rawRelyAuthMode

	err := json.Unmarshal(b, &temp)
	if err != nil {
		return err
	}

	var config authmode.RelyAuthModeInterface

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
	j.RelyAuthModeInterface = config

	return nil
}

// UnmarshalYAML implements the custom behavior for the yaml.Unmarshaler interface.
func (j *RelyAuthMode) UnmarshalYAML(value *yaml.Node) error {
	var temp rawRelyAuthMode

	err := value.Decode(&temp)
	if err != nil {
		return err
	}

	var config authmode.RelyAuthModeInterface

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
	j.RelyAuthModeInterface = config

	return nil
}

// Validate if the current instance is valid.
func (j RelyAuthMode) Validate() error {
	if j.RelyAuthModeInterface == nil {
		return authmode.ErrAuthConfigRequired
	}

	return j.RelyAuthModeInterface.Validate()
}

// JSONSchema defines a custom definition for JSON schema.
func (RelyAuthMode) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		OneOf: []*jsonschema.Schema{
			{
				Description: "Configurations for HTTP authentication with static secrets",
				Ref:         "#/$defs/RelyAuthAPIKeyConfig",
			},
			{
				Description: "Configurations to which the incoming JWT will be verified and decoded to extract the session variable claims",
				Ref:         "#/$defs/RelyAuthJWTConfig",
			},
			{
				Description: "The session variables configuration for unauthenticated users",
				Ref:         "#/$defs/RelyAuthNoAuthConfig",
			},
			{
				Description: "Configurations for the webhook authentication mode",
				Ref:         "#/$defs/RelyAuthWebhookConfig",
			},
		},
	}
}
