package authmode

// RelyAuthSettings holds global settings for the authenticators.
type RelyAuthSettings struct {
	// Strict mode, when enabled will return HTTP 401 if the token is found but unauthorized.
	// It won't fallback to the noAuth mode.
	Strict bool `json:"strict,omitempty" yaml:"strict,omitempty"`
	// The interval in seconds to reload JSON web keys from the remote URL.
	// If the value is zero or negative, disables the process.
	ReloadInterval int `json:"reloadInterval,omitempty" yaml:"reloadInterval,omitempty" jsonschema:"minimum=0,default=0"`
}
