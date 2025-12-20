package auth

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/hasura/gotel"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmetrics"
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

var tracer = gotel.NewTracer("rely-auth")

// ComposedAuthenticator represents an authenticator that composes a list of authenticators and authenticates fallback in order.
type ComposedAuthenticator struct {
	Settings         authmode.RelyAuthSettings
	Authenticators   []authmode.RelyAuthenticator
	CustomAttributes []attribute.KeyValue
}

var _ authmode.RelyAuthenticator = (*ComposedAuthenticator)(nil)

// NewComposedAuthenticator creates a new [ComposedAuthenticator] instance.
func NewComposedAuthenticator(authenticators []authmode.RelyAuthenticator) *ComposedAuthenticator {
	return &ComposedAuthenticator{
		Authenticators: authenticators,
		Settings:       authmode.RelyAuthSettings{},
	}
}

// Mode returns the auth mode of the current authenticator.
func (*ComposedAuthenticator) Mode() authmode.AuthMode {
	return authmode.AuthModeComposed
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (a *ComposedAuthenticator) Authenticate(
	ctx context.Context,
	body *authmode.AuthenticateRequestData,
) (authmode.AuthenticatedOutput, error) {
	ctx, span := tracer.Start(ctx, "Authenticate", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	if len(a.CustomAttributes) > 0 {
		span.SetAttributes(a.CustomAttributes...)
	}

	startTime := time.Now()
	metrics := authmetrics.GetRelyAuthMetrics()

	logger := gotel.GetLogger(ctx)

	var tokenNotFound bool

	for _, authenticator := range a.Authenticators {
		authMode := authenticator.Mode()
		// if auth token exists but it is unauthorized,
		// the noAuth mode is skipped with the strict mode enabled.
		if authMode == authmode.AuthModeNoAuth &&
			!tokenNotFound && a.Settings.Strict {
			break
		}

		authModeAttr := attribute.String("auth.mode", string(authMode))

		result, err := authenticator.Authenticate(ctx, body)
		if err == nil {
			latency := time.Since(startTime).Seconds()
			authIDAttr := attribute.String("auth.id", result.ID)

			metrics.RequestDuration.Record(
				ctx,
				latency,
				metric.WithAttributeSet(attribute.NewSet(
					append(
						a.CustomAttributes,
						authmetrics.AuthStatusSuccessAttribute)...,
				)),
			)

			span.SetAttributes(authModeAttr, authIDAttr)

			metrics.AuthModeTotalRequests.Add(
				ctx,
				1,
				metric.WithAttributeSet(
					attribute.NewSet(
						append(
							a.CustomAttributes,
							authmetrics.AuthStatusSuccessAttribute,
							authModeAttr,
							authIDAttr,
						)...),
				),
			)

			return result, nil
		}

		authModeTokenNotFound := errors.Is(err, authmode.ErrAuthTokenNotFound)
		tokenNotFound = tokenNotFound || authModeTokenNotFound

		logger.Debug(
			"Authentication failed",
			slog.String("error", err.Error()),
			slog.String("auth_mode", string(authMode)),
		)

		span.AddEvent("Authentication failed", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))

		if !authModeTokenNotFound {
			attrs := slices.Clone(a.CustomAttributes)
			attrs = append(
				attrs,
				authmetrics.AuthStatusFailedAttribute,
				authModeAttr,
			)

			if result.ID != "" {
				attrs = append(attrs, attribute.String("auth.id", result.ID))
			}

			metrics.AuthModeTotalRequests.Add(
				ctx,
				1,
				metric.WithAttributeSet(
					attribute.NewSet(attrs...),
				),
			)
		}
	}

	latency := time.Since(startTime).Seconds()

	metrics.RequestDuration.Record(
		ctx,
		latency,
		metric.WithAttributeSet(
			attribute.NewSet(append(a.CustomAttributes, authmetrics.AuthStatusFailedAttribute)...),
		),
	)
	span.SetStatus(codes.Error, "authentication failed")

	return authmode.AuthenticatedOutput{}, goutils.NewUnauthorizedError()
}

// Close terminates all underlying authenticator resources.
func (a *ComposedAuthenticator) Close() error {
	var errs []error

	for _, au := range a.Authenticators {
		err := au.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
