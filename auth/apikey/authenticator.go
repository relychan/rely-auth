// Package apikey implements the API key auth mode.
package apikey

import (
	"context"
	"fmt"
	"sync"

	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

var tracer = otel.Tracer("rely-auth/authenticator/api-key")

// APIKeyAuthenticator implements the authenticator with API key.
type APIKeyAuthenticator struct {
	config RelyAuthAPIKeyConfig

	// cached session variables
	sessionVariables map[string]any
	// Value of the static API key to be compared.
	value string
	mu    sync.RWMutex
}

var _ authmode.RelyAuthenticator = (*APIKeyAuthenticator)(nil)

// NewAPIKeyAuthenticator creates an API key authenticator instance.
func NewAPIKeyAuthenticator(config RelyAuthAPIKeyConfig) (*APIKeyAuthenticator, error) {
	tokenLocation, err := authmode.ValidateTokenLocation(config.TokenLocation)
	if err != nil {
		return nil, err
	}

	config.TokenLocation = tokenLocation

	result := &APIKeyAuthenticator{
		config: config,
	}

	err = result.doReload()
	if err != nil {
		return nil, err
	}

	return result, nil
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
	ctx context.Context,
	body authmode.AuthenticateRequestData,
) (authmode.AuthenticatedOutput, error) {
	_, span := tracer.Start(ctx, "APIKey")
	defer span.End()

	result := authmode.AuthenticatedOutput{
		ID: aka.config.ID,
	}

	rawToken, err := authmode.FindAuthTokenByLocation(&body, &aka.config.TokenLocation)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)

		return result, err
	}

	if rawToken != aka.getValue() {
		span.SetStatus(codes.Error, "api key does not match")

		return result, goutils.NewUnauthorizedError()
	}

	result.SessionVariables = aka.getSessionVariables()

	span.SetStatus(codes.Ok, "")

	return result, nil
}

// Reload credentials of the authenticator.
func (aka *APIKeyAuthenticator) Reload(_ context.Context) error {
	aka.mu.Lock()
	defer aka.mu.Unlock()

	return aka.doReload()
}

func (aka *APIKeyAuthenticator) doReload() error {
	mode := aka.Mode()

	value, err := aka.config.Value.Get()
	if err != nil {
		return err
	}

	if value == "" {
		return authmode.ErrAuthConfigValueRequired
	}

	aka.value = value

	sessionVariables := make(map[string]any)

	for key, envValue := range aka.config.SessionVariables {
		value, err := envValue.Get()
		if err != nil {
			return fmt.Errorf(
				"auth mode: %s; id: %s; error: failed to load session variable %s: %w",
				mode,
				aka.config.ID,
				key,
				err,
			)
		}

		sessionVariables[key] = value
	}

	aka.sessionVariables = sessionVariables

	return nil
}

func (aka *APIKeyAuthenticator) getValue() string {
	aka.mu.RLock()
	defer aka.mu.RUnlock()

	return aka.value
}

func (aka *APIKeyAuthenticator) getSessionVariables() map[string]any {
	aka.mu.RLock()
	defer aka.mu.RUnlock()

	return aka.sessionVariables
}
