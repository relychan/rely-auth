package authmode

import (
	"errors"
	"fmt"
)

const (
	// XHasuraDefaultRole is the constant string of the x-hasura-default-role key.
	XHasuraDefaultRole = "x-hasura-default-role"
	// XHasuraAllowedRoles is the constant string of the x-hasura-allowed-roles key.
	XHasuraAllowedRoles = "x-hasura-allowed-roles"
	// XHasuraRole is the constant string of the x-hasura-role key.
	XHasuraRole = "x-hasura-role"
)

var (
	// ErrAuthConfigRequired occurs when the auth config is null.
	ErrAuthConfigRequired = errors.New("auth definition is empty")
	// ErrAuthConfigValueRequired occurs when the auth value is empty.
	ErrAuthConfigValueRequired = errors.New("auth definition value is empty")
	// ErrOnlyOneNoAuthModeAllowed occurs when there are many auth config definitions with noAuth mode.
	ErrOnlyOneNoAuthModeAllowed = errors.New("only one noAuth config is allowed")
	// ErrAuthFieldRequired occurs when a field in the auth config is empty.
	ErrAuthFieldRequired = errors.New("required field")
	// ErrLocationNameRequired occurs when the name of the token location is empty.
	ErrLocationNameRequired = errors.New("name of token location is required")
	// ErrAuthTokenNotFound occurs when the API key or token is not found.
	ErrAuthTokenNotFound = errors.New("auth token not found")
	// ErrUnsupportedAuthMode occurs when the auth mode is unsupported.
	ErrUnsupportedAuthMode = errors.New("unsupported auth mode")
)

// NewAuthFieldRequiredError creates a required auth field error.
func NewAuthFieldRequiredError(authMode AuthMode, name string) error {
	return fmt.Errorf("%w %s for %s auth mode", ErrAuthFieldRequired, name, authMode)
}
