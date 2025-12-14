// Package auth defines a universal authentication manager
package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/hasura/gotel"
	"github.com/relychan/gohttpc"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/apikey"
	"github.com/relychan/rely-auth/auth/authmode"
	"github.com/relychan/rely-auth/auth/jwt"
	"github.com/relychan/rely-auth/auth/noauth"
	"github.com/relychan/rely-auth/auth/webhook"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// RelyAuthManager manages multiple authentication strategies to verify HTTP requests.
type RelyAuthManager struct {
	options               authmode.RelyAuthenticatorOptions
	settings              *authmode.RelyAuthSettings
	authenticators        []authmode.RelyAuthenticator
	requestDuration       metric.Float64Histogram
	authModeTotalRequests metric.Int64Counter
	stopChan              chan (struct{})
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

	if opts.Meter == nil {
		opts.Meter = otel.Meter("rely_auth")
	}

	manager := RelyAuthManager{
		options:  opts,
		settings: &authmode.RelyAuthSettings{},
		stopChan: make(chan struct{}),
	}

	var err error

	manager.requestDuration, err = opts.Meter.Float64Histogram(
		"rely_auth.request.duration",
		metric.WithDescription("Duration of authentication requests."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(
			0.005,
			0.01,
			0.025,
			0.05,
			0.075,
			0.1,
			0.25,
			0.5,
			0.75,
			1,
			2.5,
			5,
			7.5,
			10,
		),
	)
	if err != nil {
		return nil, err
	}

	manager.authModeTotalRequests, err = opts.Meter.Int64Counter(
		"rely_auth.request_mode.total",
		metric.WithDescription("Total number of successful auth mode requests."),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, err
	}

	hasJWK, err := manager.init(ctx, config)
	if err != nil {
		return nil, err
	}

	if hasJWK && manager.settings.ReloadInterval > 0 {
		go manager.startReloadProcess(ctx, manager.settings.ReloadInterval)
	}

	return &manager, nil
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (am *RelyAuthManager) Authenticate(
	ctx context.Context,
	body authmode.AuthenticateRequestData,
) (map[string]any, error) {
	ctx, span := tracer.Start(ctx, "Authenticate", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	startTime := time.Now()

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

			am.requestDuration.Record(
				ctx,
				latency,
				metric.WithAttributeSet(attribute.NewSet(authStatusSuccessAttribute)),
			)

			span.SetAttributes(authModeAttr, authIDAttr)

			am.authModeTotalRequests.Add(
				ctx,
				1,
				metric.WithAttributeSet(
					attribute.NewSet(authStatusSuccessAttribute, authModeAttr, authIDAttr),
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

	am.requestDuration.Record(
		ctx,
		latency,
		metric.WithAttributeSet(attribute.NewSet(authStatusFailedAttribute)),
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
	var errs []error

	if am.stopChan != nil {
		close(am.stopChan)
		am.stopChan = nil
	}

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

func (am *RelyAuthManager) init(ctx context.Context, config *RelyAuthConfig) (bool, error) {
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

			authenticator, err := apikey.NewAPIKeyAuthenticator(def)
			if err != nil {
				return false, fmt.Errorf("failed to create API Key auth %s: %w", def.ID, err)
			}

			am.authenticators = append(am.authenticators, authenticator)
		case *jwt.RelyAuthJWTConfig:
			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			if jwtAuth == nil {
				authenticator, err := jwt.NewJWTAuthenticator(ctx, nil, am.options)
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

			authenticator, err := webhook.NewWebhookAuthenticator(ctx, def, am.options)
			if err != nil {
				return false, fmt.Errorf("failed to create webhook auth %s: %w", def.ID, err)
			}

			am.authenticators = append(am.authenticators, authenticator)
		case *noauth.RelyAuthNoAuthConfig:
			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			authenticator, err := noauth.NewNoAuth(ctx, def, am.options)
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

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()

			return
		case <-am.stopChan:
			ticker.Stop()

			return
		case <-ticker.C:
			err := am.Reload(ctx)
			if err != nil {
				am.options.Logger.Error(
					"failed to reload auth credentials",
					slog.String("type", "auth-refresh-log"),
					slog.String("error", err.Error()),
				)
			}
		}
	}
}
