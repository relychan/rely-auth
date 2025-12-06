package authmode

import (
	"github.com/invopop/jsonschema"
	"github.com/relychan/goutils"
)

// AuthMode represents an authentication mode enum.
type AuthMode string

const (
	AuthModeNoAuth  AuthMode = "noAuth"
	AuthModeAPIKey  AuthMode = "apiKey"
	AuthModeJWT     AuthMode = "jwt"
	AuthModeWebhook AuthMode = "webhook"
)

var enumAuthModes = []AuthMode{AuthModeAPIKey, AuthModeJWT, AuthModeWebhook, AuthModeNoAuth}

// GetSupportedAuthModes gets the list of supported auth modes.
func GetSupportedAuthModes() []AuthMode {
	return enumAuthModes
}

// JSONSchema defines a custom definition for JSON schema.
func (AuthMode) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Description: "Authentication mode enum",
		Enum:        goutils.ToAnySlice(GetSupportedAuthModes()),
	}
}
