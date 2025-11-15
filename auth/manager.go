// Package auth defines a universal authentication manager
package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"

	"github.com/hasura/gotel"
	"github.com/relychan/gohttps"
	"github.com/relychan/gorestly"
	"github.com/relychan/rely-auth/auth/apikey"
	"github.com/relychan/rely-auth/auth/authmode"
	"github.com/relychan/rely-auth/auth/jwt"
	"github.com/relychan/rely-auth/auth/noauth"
	"github.com/relychan/rely-auth/auth/webhook"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"resty.dev/v3"
)

var tracer = gotel.NewTracer("rely-auth")

// RelyAuthManager manages multiple authentication strategies to verify HTTP requests.
type RelyAuthManager struct {
	settings       *authmode.RelyAuthSettings
	authenticators []authmode.RelyAuthenticator
	httpClient     *resty.Client
}

// NewRelyAuthManager creates a new RelyAuthManager instance from config.
func NewRelyAuthManager(config *RelyAuthConfig, logger *slog.Logger) (*RelyAuthManager, error) {
	httpClient, err := gorestly.NewClientFromConfig(
		gorestly.RestyConfig{},
		gorestly.WithLogger(logger.With("type", "auth-client")),
		gorestly.WithTracer(otel.Tracer("rely-auth/client")),
	)
	if err != nil {
		return nil, err
	}

	manager := RelyAuthManager{
		settings:   &authmode.RelyAuthSettings{},
		httpClient: httpClient,
	}

	return &manager, manager.init(config)
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (am *RelyAuthManager) Authenticate(
	ctx context.Context,
	body authmode.AuthenticateRequestData,
) (map[string]any, error) {
	ctx, span := tracer.Start(ctx, "Authenticate", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	logger := gotel.GetLogger(ctx)

	var tokenNotFound bool

	for _, authenticator := range am.authenticators {
		// if auth token exists but it is unauthorized,
		// the noAuth mode is skipped with the strict mode enabled.
		if authenticator.GetMode() == authmode.AuthModeNoAuth &&
			!tokenNotFound && am.settings.Strict {
			break
		}

		result, err := authenticator.Authenticate(ctx, body)
		if err == nil {
			return result, nil
		}

		tokenNotFound = tokenNotFound || errors.Is(err, authmode.ErrAuthTokenNotFound)

		logger.Debug(
			"Authentication failed",
			slog.String("error", err.Error()),
			slog.String("auth_mode", string(authenticator.GetMode())),
		)

		span.AddEvent("Authentication failed", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
	}

	span.SetStatus(codes.Error, "authentication failed")

	return nil, gohttps.NewUnauthorizedError()
}

// Reload credentials of the authenticator.
func (am *RelyAuthManager) Reload(ctx context.Context) error {
	var errs []error

	for _, authenticator := range am.authenticators {
		err := authenticator.Reload(ctx)
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (am *RelyAuthManager) init(config *RelyAuthConfig) error {
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
		am.settings = config.Settings
	}

	var jwtAuth *jwt.JWTAuthenticator

	for i, rawDef := range definitions {
		switch def := rawDef.RelyAuthDefinitionInterface.(type) {
		case *apikey.RelyAuthAPIKeyConfig:
			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			authenticator, err := apikey.NewAPIKeyAuthenticator(*def)
			if err != nil {
				return fmt.Errorf("failed to create API Key auth %s: %w", def.ID, err)
			}

			am.authenticators = append(am.authenticators, authenticator)
		case *jwt.RelyAuthJWTConfig:
			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			if jwtAuth == nil {
				authenticator, err := jwt.NewJWTAuthenticator(nil, am.httpClient)
				if err != nil {
					return err
				}

				jwtAuth = authenticator
				am.authenticators = append(am.authenticators, authenticator)
			}

			err := jwtAuth.Add(*def)
			if err != nil {
				return fmt.Errorf("failed to create JWT auth %s: %w", def.ID, err)
			}
		case *webhook.RelyAuthWebhookConfig:
			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			authenticator, err := webhook.NewWebhookAuthenticator(*def)
			if err != nil {
				return fmt.Errorf("failed to create webhook auth %s: %w", def.ID, err)
			}

			am.authenticators = append(am.authenticators, authenticator)
		case *noauth.RelyAuthNoAuthConfig:
			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			authenticator, err := noauth.NewNoAuth(*def)
			if err != nil {
				return fmt.Errorf("failed to create noAuth: %w", err)
			}

			am.authenticators = append(am.authenticators, authenticator)
		}
	}

	return nil
}
