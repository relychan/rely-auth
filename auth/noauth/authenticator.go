// Package noauth implements the noAuth mode.
package noauth

import (
	"context"
	"fmt"

	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
)

// NoAuth implements the authenticator with anonymous user.
type NoAuth struct {
	id string
	// Custom session variables for this auth mode.
	sessionVariables map[string]any
}

var _ authmode.RelyAuthenticator = (*NoAuth)(nil)

// NewNoAuth creates an API key authenticator instance.
func NewNoAuth(
	ctx context.Context,
	config *RelyAuthNoAuthConfig,
	options authmode.RelyAuthenticatorOptions,
) (*NoAuth, error) {
	result := &NoAuth{
		id: config.ID,
	}

	mode := result.Mode()
	sessionVariables := make(map[string]any)
	getEnvFunc := options.GetEnvFunc(ctx)

	for key, envValue := range config.SessionVariables {
		value, err := envValue.GetCustom(getEnvFunc)
		if err != nil {
			return nil, fmt.Errorf(
				"auth mode: %s; id: %s; error: failed to load session variable %s: %w",
				mode,
				config.ID,
				key,
				err,
			)
		}

		sessionVariables[key] = value
	}

	result.sessionVariables = sessionVariables

	return result, nil
}

// Mode returns the auth mode of the current authenticator.
func (*NoAuth) Mode() authmode.AuthMode {
	return authmode.AuthModeNoAuth
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (j *NoAuth) Authenticate(
	_ context.Context,
	_ authmode.AuthenticateRequestData,
) (authmode.AuthenticatedOutput, error) {
	result := authmode.AuthenticatedOutput{
		ID:               j.id,
		SessionVariables: j.sessionVariables,
	}

	return result, nil
}

// Reload credentials of the authenticator.
func (*NoAuth) Reload(_ context.Context) error {
	return nil
}

// Close handles the resources cleaning.
func (*NoAuth) Close() error {
	return nil
}

// Equal checks if the target value is equal.
func (j NoAuth) Equal(target NoAuth) bool {
	return j.id == target.id &&
		goutils.EqualMap(j.sessionVariables, target.sessionVariables, true)
}
