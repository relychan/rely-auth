// Package auth defines a universal authentication manager
package auth

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/relychan/gohttpc"
	"github.com/relychan/rely-auth/auth/apikey"
	"github.com/relychan/rely-auth/auth/authmode"
	"github.com/relychan/rely-auth/auth/jwt"
	"github.com/relychan/rely-auth/auth/noauth"
	"github.com/relychan/rely-auth/auth/webhook"
)

// RelyAuthManager manages multiple authentication strategies to verify HTTP requests.
type RelyAuthManager struct {
	authenticator *ComposedAuthenticator
	logger        *slog.Logger
	stopChan      chan struct{}
	mu            sync.Mutex
}

// NewRelyAuthManager creates a new RelyAuthManager instance from config.
func NewRelyAuthManager(
	ctx context.Context,
	config *RelyAuthConfig,
	options ...authmode.RelyAuthenticatorOption,
) (*RelyAuthManager, error) {
	opts := authmode.NewRelyAuthenticatorOptions(options...)

	if opts.HTTPClient == nil {
		clientOptions := []gohttpc.ClientOption{
			gohttpc.WithLogger(opts.Logger.With("type", "auth-client")),
			gohttpc.WithTimeout(time.Minute),
		}

		opts.HTTPClient = gohttpc.NewClient(clientOptions...)
	}

	manager := RelyAuthManager{
		authenticator: &ComposedAuthenticator{
			Settings:         authmode.RelyAuthSettings{},
			CustomAttributes: opts.CustomAttributes,
		},
		stopChan: make(chan struct{}),
		logger:   opts.Logger,
	}

	var err error

	hasJWK, err := manager.init(ctx, config, opts)
	if err != nil {
		return nil, err
	}

	if hasJWK && manager.authenticator.Settings.ReloadInterval > 0 {
		go manager.startReloadProcess(ctx, manager.authenticator.Settings.ReloadInterval)
	}

	return &manager, nil
}

// Settings return settings of the manager.
func (am *RelyAuthManager) Settings() *authmode.RelyAuthSettings {
	return &am.authenticator.Settings
}

// Authenticator returns the internal [ComposedAuthenticator] instance.
func (am *RelyAuthManager) Authenticator() *ComposedAuthenticator {
	return am.authenticator
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (am *RelyAuthManager) Authenticate(
	ctx context.Context,
	body *authmode.AuthenticateRequestData,
) (authmode.AuthenticatedOutput, error) {
	return am.authenticator.Authenticate(ctx, body)
}

// Close terminates all underlying authenticator resources.
func (am *RelyAuthManager) Close() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// already closed. Exit
	if am.stopChan == nil {
		return nil
	}

	close(am.stopChan)
	am.stopChan = nil

	return am.authenticator.Close()
}

func (am *RelyAuthManager) init(
	ctx context.Context,
	config *RelyAuthConfig,
	options authmode.RelyAuthenticatorOptions,
) (bool, error) {
	authModes := authmode.GetSupportedAuthModes()
	definitions := config.Definitions

	// Auth modes are sorted in order:
	// - API Key: comparing static keys is cheap. So it should be used first.
	// - JWT: verifying signatures is more expensive. However, because JSON web keys are stored in memory so the verification is still fast.
	// - Webhook: calling HTTP requests takes highest latency due to network side effects. It should be the lowest priority.
	// - No Auth: is always the last for unauthenticated users.
	slices.SortFunc(definitions, func(a, b RelyAuthDefinition) int {
		indexA := slices.Index(authModes, a.GetMode())
		indexB := slices.Index(authModes, b.GetMode())

		return indexA - indexB
	})

	if config.Settings != nil {
		am.authenticator.Settings = *config.Settings
	}

	var jwtAuth *jwt.JWTAuthenticator

	for i, rawDef := range definitions {
		switch def := rawDef.RelyAuthDefinitionInterface.(type) {
		case *apikey.RelyAuthAPIKeyConfig:
			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			authenticator, err := apikey.NewAPIKeyAuthenticator(ctx, def, options)
			if err != nil {
				return false, fmt.Errorf("failed to create API Key auth %s: %w", def.ID, err)
			}

			am.authenticator.Authenticators = append(am.authenticator.Authenticators, authenticator)
		case *jwt.RelyAuthJWTConfig:
			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			if jwtAuth == nil {
				authenticator, err := jwt.NewJWTAuthenticator(ctx, nil, options)
				if err != nil {
					return false, err
				}

				jwtAuth = authenticator
				am.authenticator.Authenticators = append(am.authenticator.Authenticators, authenticator)
			}

			err := jwtAuth.Add(ctx, *def)
			if err != nil {
				return false, fmt.Errorf("failed to create JWT auth %s: %w", def.ID, err)
			}
		case *webhook.RelyAuthWebhookConfig:
			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			authenticator, err := webhook.NewWebhookAuthenticator(ctx, def, options)
			if err != nil {
				return false, fmt.Errorf("failed to create webhook auth %s: %w", def.ID, err)
			}

			am.authenticator.Authenticators = append(am.authenticator.Authenticators, authenticator)
		case *noauth.RelyAuthNoAuthConfig:
			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			authenticator, err := noauth.NewNoAuth(ctx, def, options)
			if err != nil {
				return false, fmt.Errorf("failed to create noAuth: %w", err)
			}

			am.authenticator.Authenticators = append(am.authenticator.Authenticators, authenticator)
		}
	}

	return jwtAuth != nil && jwtAuth.HasJWK(), nil
}

func (am *RelyAuthManager) startReloadProcess(ctx context.Context, reloadInterval int) {
	ticker := time.NewTicker(time.Duration(reloadInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-am.stopChan:
			return
		case <-ticker.C:
			var isStop bool

			am.mu.Lock()
			isStop = am.stopChan == nil
			am.mu.Unlock()

			if isStop {
				return
			}

			err := am.authenticator.Reload(ctx)
			if err != nil {
				am.logger.Error(
					"failed to reload auth credentials",
					slog.String("type", "auth-refresh-log"),
					slog.String("error", err.Error()),
				)
			}
		}
	}
}
