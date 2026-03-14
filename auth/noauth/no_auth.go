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

package noauth

import (
	"github.com/hasura/goenvconf"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
)

// RelyAuthNoAuthConfig contains the session variables configuration for unauthenticated users.
type RelyAuthNoAuthConfig struct {
	// Unique identity of the auth config.
	// If not set, ID will be the index of the array.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`
	// Authentication mode which is always noAuth.
	Mode authmode.AuthMode `json:"mode" jsonschema:"enum=noAuth" yaml:"mode"`
	// Custom session variables for this auth mode.
	SessionVariables map[string]goenvconf.EnvAny `json:"sessionVariables" yaml:"sessionVariables"`
}

var _ authmode.RelyAuthModeInterface = (*RelyAuthNoAuthConfig)(nil)

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
