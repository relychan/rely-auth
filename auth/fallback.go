package auth

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"github.com/hasura/gotel"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmetrics"
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

var tracer = gotel.NewTracer("rely-auth")

// FallbackAuthenticator represents an authenticator that receives a list of authenticators and authenticates fallback in order.
type FallbackAuthenticator struct {
	Authenticators   []authmode.RelyAuthenticator
	CustomAttributes []attribute.KeyValue
}

var _ authmode.RelyAuthenticator = (*FallbackAuthenticator)(nil)

// NewComposedAuthenticator creates a new [ComposedAuthenticator] instance.
func NewComposedAuthenticator(authenticators []authmode.RelyAuthenticator) *FallbackAuthenticator {
	return &FallbackAuthenticator{
		Authenticators: authenticators,
	}
}

// Mode returns the auth mode of the current authenticator.
func (*FallbackAuthenticator) Mode() authmode.AuthMode {
	return authmode.AuthModeFallback
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (a *FallbackAuthenticator) Authenticate(
	ctx context.Context,
	body *authmode.AuthenticateRequestData,
) (authmode.AuthenticatedOutput, error) {
	metrics := authmetrics.GetRelyAuthMetrics()
	logger := gotel.GetLogger(ctx)
	span := trace.SpanFromContext(ctx)
	desiredAuthMode := authmode.GetAuthModeHeader(body.Headers)
	desiredAuthID := body.Headers[authmode.XRelyAuthID]

	var finalError error

	for _, authenticator := range a.Authenticators {
		authMode := authenticator.Mode()
		if desiredAuthMode != "" && desiredAuthMode != string(authMode) {
			continue
		}

		// if the request specifies an explicit authenticator ID,
		// only authenticates the matched authenticator and responds
		if desiredAuthID != "" {
			if slices.Contains(authenticator.IDs(), desiredAuthID) {
				result, _, err := a.authenticateOne(ctx, body, authenticator, span, metrics)

				return result, err
			}

			continue
		}

		result, isTokenNotFound, err := a.authenticateOne(
			ctx,
			body,
			authenticator,
			span,
			metrics,
		)
		if err == nil {
			logger.Debug(
				"Authenticated",
				slog.Any("session_variables", result.SessionVariables),
				slog.String("auth_mode", string(authMode)),
			)

			return result, nil
		}

		// Return the last error that the request token was found, yet invalid.
		if finalError == nil || !isTokenNotFound {
			finalError = err
		}

		logger.Debug(
			"Authentication failed",
			slog.String("error", err.Error()),
			slog.String("auth_mode", string(authMode)),
		)
	}

	if finalError == nil {
		finalError = goutils.NewUnauthorizedError()
	}

	return authmode.AuthenticatedOutput{}, finalError
}

// IDs returns identities of this authenticator.
func (a *FallbackAuthenticator) IDs() []string {
	results := []string{}

	for _, au := range a.Authenticators {
		results = append(results, au.IDs()...)
	}

	return results
}

// Close terminates all underlying authenticator resources.
func (a *FallbackAuthenticator) Close() error {
	var errs []error

	for _, au := range a.Authenticators {
		err := au.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (a *FallbackAuthenticator) authenticateOne(
	ctx context.Context,
	body *authmode.AuthenticateRequestData,
	authenticator authmode.RelyAuthenticator,
	span trace.Span,
	metrics *authmetrics.RelyAuthMetrics,
) (authmode.AuthenticatedOutput, bool, error) {
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

		return result, false, nil
	}

	span.AddEvent("Authentication failed", trace.WithAttributes(
		attribute.String("error", err.Error()),
	))

	isTokenNotFound := errors.Is(err, authmode.ErrAuthTokenNotFound)

	if !isTokenNotFound {
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

	return result, isTokenNotFound, err
}
