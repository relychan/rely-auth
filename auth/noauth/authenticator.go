// Package noauth implements the noAuth mode.
package noauth

import (
	"context"
	"fmt"
	"sync"

	"github.com/relychan/rely-auth/auth/authmode"
)

// NoAuth implements the authenticator with anonymous user.
type NoAuth struct {
	config RelyAuthNoAuthConfig
	// Custom session variables for this auth mode.
	sessionVariables map[string]any
	mu               sync.RWMutex
}

var _ authmode.RelyAuthenticator = (*NoAuth)(nil)

// NewNoAuth creates an API key authenticator instance.
func NewNoAuth(config RelyAuthNoAuthConfig) (*NoAuth, error) {
	result := &NoAuth{
		config: config,
	}

	err := result.doReload(context.Background())
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetMode returns the auth mode of the current authenticator.
func (*NoAuth) GetMode() authmode.AuthMode {
	return authmode.AuthModeNoAuth
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (j *NoAuth) Authenticate(
	_ context.Context,
	_ authmode.AuthenticateRequestData,
) (map[string]any, error) {
	return j.getSessionVariables(), nil
}

// Close handles the resources cleaning.
func (*NoAuth) Close() error {
	return nil
}

// Reload credentials of the authenticator.
func (j *NoAuth) Reload(ctx context.Context) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	return j.doReload(ctx)
}

func (j *NoAuth) doReload(context.Context) error {
	mode := j.GetMode()
	sessionVariables := make(map[string]any)

	for key, envValue := range j.config.SessionVariables {
		value, err := envValue.Get()
		if err != nil {
			return fmt.Errorf(
				"auth mode: %s; id: %s; error: failed to load session variable %s: %w",
				mode,
				j.config.ID,
				key,
				err,
			)
		}

		sessionVariables[key] = value
	}

	j.sessionVariables = sessionVariables

	return nil
}

func (j *NoAuth) getSessionVariables() map[string]any {
	j.mu.RLock()
	defer j.mu.RUnlock()

	return j.sessionVariables
}
