package apikey

import (
	"github.com/hasura/goenvconf"
	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/goutils"
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

// IsZero if the current instance is empty.
func (j RelyAuthAPIKeyConfig) IsZero() bool {
	return j.Value.IsZero() &&
		j.TokenLocation.IsZero() &&
		len(j.SessionVariables) == 0 &&
		j.Description == "" &&
		j.ID == "" &&
		j.Mode == ""
}

// Equal checks if the target value is equal.
func (j RelyAuthAPIKeyConfig) Equal(target RelyAuthAPIKeyConfig) bool {
	return j.Mode == target.Mode &&
		j.TokenLocation.Equal(target.TokenLocation) &&
		j.Value.Equal(target.Value) &&
		goutils.EqualMap(j.SessionVariables, target.SessionVariables, true)
}
