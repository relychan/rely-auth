package authmode

// RelyAuthSettings holds global settings for the authenticators.
type RelyAuthSettings struct {
	// Strict mode, when enabled will return HTTP 401 if the token is found but unauthorized.
	// It won't fallback to the noAuth mode.
	Strict bool `json:"strict,omitempty" yaml:"strict,omitempty"`
}
