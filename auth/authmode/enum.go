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

package authmode

// AuthMode represents an authentication mode enum.
type AuthMode string

const (
	AuthModeNoAuth   AuthMode = "noAuth"
	AuthModeAPIKey   AuthMode = "apiKey"
	AuthModeJWT      AuthMode = "jwt"
	AuthModeWebhook  AuthMode = "webhook"
	AuthModeCompose  AuthMode = "compose"
	AuthModeFallback AuthMode = "fallback"
)

var enumAuthModes = []AuthMode{AuthModeAPIKey, AuthModeJWT, AuthModeWebhook, AuthModeNoAuth}

// GetSupportedAuthModes gets the list of supported auth modes.
func GetSupportedAuthModes() []AuthMode {
	return enumAuthModes
}
