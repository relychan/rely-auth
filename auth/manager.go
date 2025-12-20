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

	"github.com/relychan/gohttpc"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/apikey"
	"github.com/relychan/rely-auth/auth/authmetrics"
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
	settings      authmode.RelyAuthSettings
	authenticator *ComposedAuthenticator
	noAuth        *noauth.NoAuth
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
			CustomAttributes: opts.CustomAttributes,
		},
		settings: authmode.RelyAuthSettings{},
		stopChan: make(chan struct{}),
		logger:   opts.Logger,
	}

	err := manager.init(ctx, config, opts)
	if err != nil {
		return nil, err
	}

	if jwt.GetJWKSCount() > 0 && manager.settings.ReloadInterval > 0 {
		go manager.startReloadProcess(ctx, manager.settings.ReloadInterval)
	}

	return &manager, nil
}

// Settings return settings of the manager.
func (am *RelyAuthManager) Settings() *authmode.RelyAuthSettings {
	return &am.settings
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
	ctx, span := tracer.Start(ctx, "Authenticate", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	if len(am.authenticator.CustomAttributes) > 0 {
		span.SetAttributes(am.authenticator.CustomAttributes...)
	}

	var (
		output authmode.AuthenticatedOutput
		err    error
	)

	startTime := time.Now()
	metrics := authmetrics.GetRelyAuthMetrics()

	if len(am.authenticator.Authenticators) == 0 {
		output, err = am.noAuth.Authenticate(ctx, body)
	} else {
		output, err = am.authenticator.Authenticate(ctx, body)
		if err != nil && (am.noAuth == nil ||
			// In the strict mode, if the request token was found but invalid,
			// return unauthorized error instead of the unauthenticated role.
			(am.settings.Strict && !errors.Is(err, authmode.ErrAuthTokenNotFound))) {
			metrics.RequestDuration.Record(
				ctx,
				time.Since(startTime).Seconds(),
				metric.WithAttributeSet(attribute.NewSet(
					append(
						am.authenticator.CustomAttributes,
						authmetrics.AuthStatusFailedAttribute)...,
				)),
			)

			span.SetAttributes(authmetrics.NewAuthModeAttribute(output.Mode))
			span.SetStatus(codes.Error, "authentication failed")
			span.RecordError(err)

			return output, goutils.NewUnauthorizedError()
		}

		if err != nil && am.noAuth != nil {
			output, err = am.noAuth.Authenticate(ctx, body)
		}
	}

	metrics.RequestDuration.Record(
		ctx,
		time.Since(startTime).Seconds(),
		metric.WithAttributeSet(attribute.NewSet(
			append(
				am.authenticator.CustomAttributes,
				authmetrics.AuthStatusSuccessAttribute)...,
		)),
	)

	span.SetAttributes(authmetrics.NewAuthIDAttribute(output.ID))
	span.SetAttributes(authmetrics.NewAuthModeAttribute(output.Mode))
	span.SetStatus(codes.Ok, "")

	return output, err
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

	authErr := am.authenticator.Close()
	jwsErr := jwt.CloseJWKS()

	return errors.Join(authErr, jwsErr)
}

func (am *RelyAuthManager) init(
	ctx context.Context,
	config *RelyAuthConfig,
	options authmode.RelyAuthenticatorOptions,
) error {
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
		am.settings = *config.Settings
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
				return fmt.Errorf("failed to create API Key auth %s: %w", def.ID, err)
			}

			am.authenticator.Authenticators = append(am.authenticator.Authenticators, authenticator)
		case *jwt.RelyAuthJWTConfig:
			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			if jwtAuth == nil {
				authenticator, err := jwt.NewJWTAuthenticator(ctx, nil, options)
				if err != nil {
					return err
				}

				jwtAuth = authenticator
				am.authenticator.Authenticators = append(am.authenticator.Authenticators, authenticator)
			}

			err := jwtAuth.Add(ctx, *def)
			if err != nil {
				return fmt.Errorf("failed to create JWT auth %s: %w", def.ID, err)
			}
		case *webhook.RelyAuthWebhookConfig:
			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			authenticator, err := webhook.NewWebhookAuthenticator(ctx, def, options)
			if err != nil {
				return fmt.Errorf("failed to create webhook auth %s: %w", def.ID, err)
			}

			am.authenticator.Authenticators = append(am.authenticator.Authenticators, authenticator)
		case *noauth.RelyAuthNoAuthConfig:
			if am.noAuth != nil {
				return authmode.ErrOnlyOneNoAuthModeAllowed
			}

			if def.ID == "" {
				def.ID = strconv.Itoa(i)
			}

			authenticator, err := noauth.NewNoAuth(ctx, def, options)
			if err != nil {
				return fmt.Errorf("failed to create noAuth: %w", err)
			}

			am.noAuth = authenticator
		}
	}

	return nil
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

			err := jwt.ReloadJWKS(ctx)
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
