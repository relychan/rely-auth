package auth

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"github.com/hasura/gotel"
	"github.com/relychan/rely-auth/auth/authmetrics"
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

var tracer = gotel.NewTracer("rely-auth")

// ComposedAuthenticator represents an authenticator that composes a list of authenticators and authenticates fallback in order.
type ComposedAuthenticator struct {
	Authenticators   []authmode.RelyAuthenticator
	CustomAttributes []attribute.KeyValue
}

var _ authmode.RelyAuthenticator = (*ComposedAuthenticator)(nil)

// NewComposedAuthenticator creates a new [ComposedAuthenticator] instance.
func NewComposedAuthenticator(authenticators []authmode.RelyAuthenticator) *ComposedAuthenticator {
	return &ComposedAuthenticator{
		Authenticators: authenticators,
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
	metrics := authmetrics.GetRelyAuthMetrics()
	logger := gotel.GetLogger(ctx)
	span := trace.SpanFromContext(ctx)

	var finalError error

	for _, authenticator := range a.Authenticators {
		authMode := authenticator.Mode()
		authModeAttr := authmetrics.NewAuthModeAttribute(authMode)

		result, err := authenticator.Authenticate(ctx, body)
		if err == nil {
			authIDAttr := authmetrics.NewAuthIDAttribute(result.ID)

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
		// Return the last error that the request token was found, yet invalid.
		if finalError == nil || !authModeTokenNotFound {
			finalError = err
		}

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

	return authmode.AuthenticatedOutput{}, finalError
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
