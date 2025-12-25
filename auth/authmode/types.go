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
	// ErrEmptyAllowedIPs occurs when the allowed IPs config is empty.
	ErrEmptyAllowedIPs = errors.New("allowed IPs config is empty")
	// ErrInvalidSubnet occurs when the subnet string is invalid.
	ErrInvalidSubnet = errors.New("invalid IP or subnet")
	// ErrInvalidIP occurs when the IP string is invalid.
	ErrInvalidIP = errors.New("invalid IP")
	// ErrIPNotFound occurs when the IP does not exist in request headers.
	ErrIPNotFound = errors.New("ip not found")
	// ErrDisallowedIP occurs when the IP string does not satisfy the allow list.
	ErrDisallowedIP = errors.New("ip address does not satisfy the allow list")
	// ErrHostOriginRequired occurs when the host origin does not exist in request headers.
	ErrHostOriginRequired = errors.New("host origin is empty")
	// ErrDisallowedOrigin occurs when the origin string does not satisfy the allow list.
	ErrDisallowedOrigin = errors.New("host origin does not satisfy the allow list")
)

// NewAuthFieldRequiredError creates a required auth field error.
func NewAuthFieldRequiredError(authMode AuthMode, name string) error {
	return fmt.Errorf("%w %s for %s auth mode", ErrAuthFieldRequired, name, authMode)
}
