package apikey

import (
	"github.com/hasura/goenvconf"
	"github.com/relychan/gorestly/authc/authscheme"
	"github.com/relychan/rely-auth/auth/authmode"
)

// RelyAuthAPIKeyConfig contains configurations for HTTP authentication with static secrets.
type RelyAuthAPIKeyConfig struct {
	authscheme.TokenLocation `yaml:",inline"`

	// Unique identity of the auth config.
	// If not set, ID will be the index of the array.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`
	// Authentication mode which is always apiKey.
	Mode authmode.AuthMode `json:"mode" jsonschema:"enum=apiKey" yaml:"mode"`
	// Brief description of the auth config.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Custom session variables for this auth mode.
	SessionVariables map[string]goenvconf.EnvAny `json:"sessionVariables" yaml:"sessionVariables"`
	// Value of the static API key to be compared.
	Value goenvconf.EnvString `json:"value" yaml:"value"`
}

var _ authmode.RelyAuthDefinitionInterface = (*RelyAuthAPIKeyConfig)(nil)

// NewRelyAuthAPIKeyConfig creates a new APIKeyAuthConfig instance.
func NewRelyAuthAPIKeyConfig(
	location authscheme.TokenLocation,
	value goenvconf.EnvString,
	sessionVariables map[string]goenvconf.EnvAny,
) *RelyAuthAPIKeyConfig {
	return &RelyAuthAPIKeyConfig{
		TokenLocation:    location,
		Mode:             authmode.AuthModeAPIKey,
		Value:            value,
		SessionVariables: sessionVariables,
	}
}

// Validate if the current instance is valid.
func (j RelyAuthAPIKeyConfig) Validate() error {
	mode := j.GetMode()

	if j.Name == "" {
		return authmode.NewAuthFieldRequiredError(mode, "name")
	}

	err := j.In.Validate()
	if err != nil {
		return err
	}

	if j.Value.IsZero() {
		return authmode.NewAuthFieldRequiredError(mode, "value")
	}

	return nil
}

// GetMode returns the auth mode of the current config.
func (RelyAuthAPIKeyConfig) GetMode() authmode.AuthMode {
	return authmode.AuthModeAPIKey
}
