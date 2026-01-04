// Package apikey implements the API key auth mode.
package apikey

import (
	"context"
	"errors"
	"fmt"

	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
)

var errAPIKeyNotMatched = errors.New("api key does not match")

// APIKeyAuthenticator implements the authenticator with API key.
type APIKeyAuthenticator struct {
	id            string
	tokenLocation authscheme.TokenLocation
	// cached session variables
	sessionVariables map[string]any
	// Value of the static API key to be compared.
	value string
}

var _ authmode.RelyAuthenticator = (*APIKeyAuthenticator)(nil)

// NewAPIKeyAuthenticator creates an API key authenticator instance.
func NewAPIKeyAuthenticator(
	config *RelyAuthAPIKeyConfig,
	options authmode.RelyAuthenticatorOptions,
) (*APIKeyAuthenticator, error) {
	tokenLocation, err := authmode.ValidateTokenLocation(config.TokenLocation)
	if err != nil {
		return nil, err
	}

	config.TokenLocation = tokenLocation
	getEnvFunc := options.GetEnvFunc()

	value, err := config.Value.GetCustom(getEnvFunc)
	if err != nil {
		return nil, err
	}

	if value == "" {
		return nil, authmode.ErrAuthConfigValueRequired
	}

	sessionVariables := make(map[string]any)

	for key, envValue := range config.SessionVariables {
		v, err := envValue.GetCustom(getEnvFunc)
		if err != nil {
			return nil, fmt.Errorf(
				"auth mode: %s; id: %s; error: failed to load session variable %s: %w",
				authmode.AuthModeAPIKey,
				config.ID,
				key,
				err,
			)
		}

		sessionVariables[key] = v
	}

	result := &APIKeyAuthenticator{
		id:               config.ID,
		tokenLocation:    config.TokenLocation,
		sessionVariables: sessionVariables,
		value:            value,
	}

	return result, nil
}

// Equal checks if the target value is equal.
func (aka APIKeyAuthenticator) Equal(target APIKeyAuthenticator) bool {
	return aka.id == target.id &&
		aka.tokenLocation.Equal(target.tokenLocation) &&
		aka.value == target.value &&
		goutils.EqualMap(aka.sessionVariables, target.sessionVariables, true)
}

// IDs returns identities of this authenticator.
func (aka *APIKeyAuthenticator) IDs() []string {
	return []string{aka.id}
}

// Mode returns the auth mode of the current authenticator.
func (*APIKeyAuthenticator) Mode() authmode.AuthMode {
	return authmode.AuthModeAPIKey
}

// Close handles the resources cleaning.
func (*APIKeyAuthenticator) Close() error {
	return nil
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (aka *APIKeyAuthenticator) Authenticate(
	_ context.Context,
	body *authmode.AuthenticateRequestData,
) (authmode.AuthenticatedOutput, error) {
	result := authmode.AuthenticatedOutput{
		ID:   aka.id,
		Mode: aka.Mode(),
	}

	rawToken, err := authmode.FindAuthTokenByLocation(body, &aka.tokenLocation)
	if err != nil {
		return result, err
	}

	if rawToken != aka.value {
		return result, errAPIKeyNotMatched
	}

	result.SessionVariables = aka.sessionVariables

	return result, nil
}
