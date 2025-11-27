// Package jwt implements the authenticator for the JWT auth mode
package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/relychan/gohttpc"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

var tracer = otel.Tracer("rely-auth/authenticator/jwt")

// JWTAuthenticator implements the authenticator with JWT key.
type JWTAuthenticator struct {
	keySets    map[string][]*JWTKeySet
	httpClient *gohttpc.Client
}

var _ authmode.RelyAuthenticator = (*JWTAuthenticator)(nil)

// NewJWTAuthenticator creates a JWT authenticator instance.
func NewJWTAuthenticator(
	configs []RelyAuthJWTConfig,
	httpClient *gohttpc.Client,
) (*JWTAuthenticator, error) {
	result := &JWTAuthenticator{
		httpClient: httpClient,
	}

	for _, config := range configs {
		err := result.doAdd(config)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// Mode returns the auth mode of the current authenticator.
func (*JWTAuthenticator) Mode() authmode.AuthMode {
	return authmode.AuthModeJWT
}

// Close handles the resources cleaning.
func (ja *JWTAuthenticator) Close() error {
	errs := []error{}

	for _, groups := range ja.keySets {
		for _, keyset := range groups {
			err := keyset.Close()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", keyset.config.ID, err))
			}
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (ja *JWTAuthenticator) Authenticate(
	ctx context.Context,
	body authmode.AuthenticateRequestData,
) (authmode.AuthenticatedOutput, error) {
	_, span := tracer.Start(ctx, "JWT")
	defer span.End()

	for _, group := range ja.keySets {
		output := authmode.AuthenticatedOutput{}
		tokenLocation := group[0].GetConfig().TokenLocation

		rawToken, err := authmode.FindAuthTokenByLocation(&body, &tokenLocation)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())

			return output, err
		}

		algorithms := []jose.SignatureAlgorithm{}

		for _, keyset := range group {
			algorithms = append(algorithms, keyset.GetSignatureAlgorithms()...)
		}

		slices.Sort(algorithms)
		algorithms = slices.Compact(algorithms)

		sig, err := jose.ParseSigned(rawToken, algorithms)
		if err != nil {
			span.SetStatus(codes.Error, "failed to parse signed token")
			span.RecordError(err)

			return output, err
		}

		var claims jwt.Claims

		err = json.Unmarshal(sig.UnsafePayloadWithoutVerification(), &claims)
		if err != nil {
			span.SetStatus(codes.Error, "failed to decode jwt payload")
			span.RecordError(err)

			return output, err
		}

		for _, key := range group {
			err := key.ValidateClaims(&claims)
			if err != nil {
				continue
			}

			verifiedBytes, err := key.VerifySignature(ctx, sig)
			if err != nil {
				continue
			}

			sessionVariables, err := key.TransformClaims(verifiedBytes)
			if err != nil {
				span.SetStatus(codes.Error, "failed to transform claims")
				span.RecordError(err)

				return output, err
			}

			output.ID = key.config.ID
			output.SessionVariables = sessionVariables

			span.SetStatus(codes.Ok, "")

			return output, nil
		}
	}

	span.SetStatus(codes.Error, "unauthorized")

	return authmode.AuthenticatedOutput{}, goutils.NewUnauthorizedError()
}

// Reload credentials of the authenticator.
func (ja *JWTAuthenticator) Reload(ctx context.Context) error {
	for _, group := range ja.keySets {
		for _, keySet := range group {
			err := keySet.Reload(ctx)
			if err != nil {
				slog.Warn(err.Error())
			}
		}
	}

	return nil
}

// Add a new JWT authenticator from config.
func (ja *JWTAuthenticator) Add(config RelyAuthJWTConfig) error {
	return ja.doAdd(config)
}

func (ja *JWTAuthenticator) doAdd(config RelyAuthJWTConfig) error {
	tokenLocation, err := authmode.ValidateTokenLocation(config.TokenLocation)
	if err != nil {
		return err
	}

	config.TokenLocation = tokenLocation

	groupKey := strings.Join([]string{
		string(tokenLocation.In),
		tokenLocation.Name,
		tokenLocation.Scheme,
	},
		":")

	if ja.keySets == nil {
		ja.keySets = map[string][]*JWTKeySet{}
	}

	keySet, err := NewJWTKeySet(&config, ja.httpClient)
	if err != nil {
		return err
	}

	ja.keySets[groupKey] = append(ja.keySets[groupKey], keySet)

	return nil
}
