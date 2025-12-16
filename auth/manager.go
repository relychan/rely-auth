// Package auth defines a universal authentication manager
package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/hasura/gotel"
	"github.com/relychan/gohttpc"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/apikey"
	"github.com/relychan/rely-auth/auth/authmode"
	"github.com/relychan/rely-auth/auth/jwt"
	"github.com/relychan/rely-auth/auth/noauth"
	"github.com/relychan/rely-auth/auth/webhook"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// RelyAuthManager manages multiple authentication strategies to verify HTTP requests.
type RelyAuthManager struct {
	settings         *authmode.RelyAuthSettings
	authenticators   []authmode.RelyAuthenticator
	customAttributes []attribute.KeyValue
	logger           *slog.Logger
	stopChan         chan struct{}
	mu               sync.Mutex
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
		settings:         &authmode.RelyAuthSettings{},
		stopChan:         make(chan struct{}),
		logger:           opts.Logger,
		customAttributes: opts.CustomAttributes,
	}

	var err error

	hasJWK, err := manager.init(ctx, config, opts)
	if err != nil {
		return nil, err
	}

	if hasJWK && manager.settings.ReloadInterval > 0 {
		go manager.startReloadProcess(ctx, manager.settings.ReloadInterval)
	}

	return &manager, nil
}

// Settings return settings of the manager.
func (am *RelyAuthManager) Settings() *authmode.RelyAuthSettings {
	return am.settings
}

// Authenticators return authenticators of the manager.
func (am *RelyAuthManager) Authenticators() []authmode.RelyAuthenticator {
	return am.authenticators
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (am *RelyAuthManager) Authenticate(
	ctx context.Context,
	body authmode.AuthenticateRequestData,
) (map[string]any, error) {
	ctx, span := tracer.Start(ctx, "Authenticate", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	if len(am.customAttributes) > 0 {
		span.SetAttributes(am.customAttributes...)
	}

	startTime := time.Now()
	metrics := GetRelyAuthMetrics()

	logger := gotel.GetLogger(ctx)

	var tokenNotFound bool

	for _, authenticator := range am.authenticators {
		authMode := authenticator.Mode()
		// if auth token exists but it is unauthorized,
		// the noAuth mode is skipped with the strict mode enabled.
		if authMode == authmode.AuthModeNoAuth &&
			!tokenNotFound && am.settings.Strict {
			break
		}

		result, err := authenticator.Authenticate(ctx, body)
		if err == nil {
			latency := time.Since(startTime).Seconds()
			authModeAttr := attribute.String("auth.mode", string(authMode))
			authIDAttr := attribute.String("auth.id", result.ID)

			metrics.RequestDuration.Record(
				ctx,
				latency,
				metric.WithAttributeSet(
					attribute.NewSet(append(am.customAttributes, authStatusSuccessAttribute)...,
					)),
			)

			span.SetAttributes(authModeAttr, authIDAttr)

			metrics.AuthModeTotalRequests.Add(
				ctx,
				1,
				metric.WithAttributeSet(
					attribute.NewSet(
						append(
							am.customAttributes,
							authStatusSuccessAttribute,
							authModeAttr,
							authIDAttr,
						)...),
				),
			)

			return result.SessionVariables, nil
		}

		tokenNotFound = tokenNotFound || errors.Is(err, authmode.ErrAuthTokenNotFound)

		logger.Debug(
			"Authentication failed",
			slog.String("error", err.Error()),
			slog.String("auth_mode", string(authMode)),
		)

		span.AddEvent("Authentication failed", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
	}

	latency := time.Since(startTime).Seconds()

	metrics.RequestDuration.Record(
		ctx,
		latency,
		metric.WithAttributeSet(
			attribute.NewSet(append(am.customAttributes, authStatusFailedAttribute)...),
		),
	)
	span.SetStatus(codes.Error, "authentication failed")

	return nil, goutils.NewUnauthorizedError()
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

// Close terminates all underlying authenticator resources.
func (am *RelyAuthManager) Close() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// already closed. Exit
	if am.stopChan == nil {
		return nil
	}

	var errs []error

	close(am.stopChan)
	am.stopChan = nil

	for _, au := range am.authenticators {
		err := au.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	default:
		return errors.Join(errs...)
	}
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
		am.settings = config.Settings
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

			am.authenticators = append(am.authenticators, authenticator)
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
				am.authenticators = append(am.authenticators, authenticator)
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

			am.authenticators = append(am.authenticators, authenticator)
		case *noauth.RelyAuthNoAuthConfig:
			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			authenticator, err := noauth.NewNoAuth(ctx, def, options)
			if err != nil {
				return false, fmt.Errorf("failed to create noAuth: %w", err)
			}

			am.authenticators = append(am.authenticators, authenticator)
		}
	}

	return jwtAuth != nil && jwtAuth.HasJWK(), nil
}

func (am *RelyAuthManager) startReloadProcess(ctx context.Context, reloadInterval int) {
	ticker := time.NewTicker(time.Duration(reloadInterval) * time.Minute)
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

			err := am.Reload(ctx)
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
