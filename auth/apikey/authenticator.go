// Package apikey implements the API key auth mode.
package apikey

import (
	"context"
	"fmt"

	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

var tracer = otel.Tracer("rely-auth/authenticator/api-key")

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
func NewAPIKeyAuthenticator(config *RelyAuthAPIKeyConfig) (*APIKeyAuthenticator, error) {
	tokenLocation, err := authmode.ValidateTokenLocation(config.TokenLocation)
	if err != nil {
		return nil, err
	}

	config.TokenLocation = tokenLocation

	value, err := config.Value.Get()
	if err != nil {
		return nil, err
	}

	if value == "" {
		return nil, authmode.ErrAuthConfigValueRequired
	}

	sessionVariables := make(map[string]any)

	for key, envValue := range config.SessionVariables {
		v, err := envValue.Get()
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

// Mode returns the auth mode of the current authenticator.
func (*APIKeyAuthenticator) Mode() authmode.AuthMode {
	return authmode.AuthModeAPIKey
}

// Reload credentials of the authenticator.
func (*APIKeyAuthenticator) Reload(_ context.Context) error {
	return nil
}

// Close handles the resources cleaning.
func (*APIKeyAuthenticator) Close() error {
	return nil
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (aka *APIKeyAuthenticator) Authenticate(
	ctx context.Context,
	body authmode.AuthenticateRequestData,
) (authmode.AuthenticatedOutput, error) {
	_, span := tracer.Start(ctx, "APIKey")
	defer span.End()

	result := authmode.AuthenticatedOutput{
		ID: aka.id,
	}

	rawToken, err := authmode.FindAuthTokenByLocation(&body, &aka.tokenLocation)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)

		return result, err
	}

	if rawToken != aka.value {
		span.SetStatus(codes.Error, "api key does not match")

		return result, goutils.NewUnauthorizedError()
	}

	result.SessionVariables = aka.sessionVariables

	span.SetStatus(codes.Ok, "")

	return result, nil
}
