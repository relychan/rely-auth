// Copyright 2026 RelyChan Pte. Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apikey

import (
	"github.com/hasura/goenvconf"
	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
)

// RelyAuthAPIKeyConfig contains configurations for HTTP authentication with static secrets.
type RelyAuthAPIKeyConfig struct {
	// Unique identity of the auth config.
	// If not set, ID will be the index of the array.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`
	// Authentication mode which is always apiKey.
	Mode authmode.AuthMode `json:"mode" jsonschema:"enum=apiKey" yaml:"mode"`
	// Brief description of the auth config.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Source of the authentication token.
	TokenLocation authscheme.TokenLocation `json:"tokenLocation" yaml:"tokenLocation"`
	// Custom session variables for this auth mode.
	SessionVariables map[string]goenvconf.EnvAny `json:"sessionVariables" yaml:"sessionVariables"`
	// Value of the static API key to be compared.
	Value goenvconf.EnvString `json:"value" yaml:"value"`
}

var _ authmode.RelyAuthModeInterface = (*RelyAuthAPIKeyConfig)(nil)

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

	err := j.TokenLocation.Validate()
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
