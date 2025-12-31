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
