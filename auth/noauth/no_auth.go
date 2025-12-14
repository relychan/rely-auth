package noauth

import (
	"github.com/hasura/goenvconf"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
)

// RelyAuthNoAuthConfig contains the definition config for unauthenticated users.
type RelyAuthNoAuthConfig struct {
	// Unique identity of the auth config.
	// If not set, ID will be the index of the array.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`
	// Authentication mode which is always noAuth.
	Mode authmode.AuthMode `json:"mode" jsonschema:"enum=noAuth" yaml:"mode"`
	// Custom session variables for this auth mode.
	SessionVariables map[string]goenvconf.EnvAny `json:"sessionVariables" yaml:"sessionVariables"`
}

var _ authmode.RelyAuthDefinitionInterface = (*RelyAuthNoAuthConfig)(nil)

// NewNoAuthDefinition creates a new NoAuthConfig instance.
func NewNoAuthDefinition(sessionVariables map[string]goenvconf.EnvAny) *RelyAuthNoAuthConfig {
	return &RelyAuthNoAuthConfig{
		SessionVariables: sessionVariables,
	}
}

// Validate if the current instance is valid.
func (RelyAuthNoAuthConfig) Validate() error {
	return nil
}

// GetMode get the auth mode of the current config.
func (RelyAuthNoAuthConfig) GetMode() authmode.AuthMode {
	return authmode.AuthModeNoAuth
}

// IsZero if the current instance is empty.
func (na RelyAuthNoAuthConfig) IsZero() bool {
	return na.Mode == "" && na.ID == "" &&
		len(na.SessionVariables) == 0
}

// Equal checks if the target value is equal.
func (na RelyAuthNoAuthConfig) Equal(target RelyAuthNoAuthConfig) bool {
	return na.ID == target.ID &&
		na.Mode == target.Mode &&
		goutils.EqualMap(na.SessionVariables, target.SessionVariables, true)
}
