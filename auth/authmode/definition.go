// Package authmode defines common types and utilities for auth modes.
package authmode

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/hasura/goenvconf"
	"github.com/relychan/gohttpc"
	"github.com/relychan/goutils"
	"go.opentelemetry.io/otel/attribute"
)

// AuthenticateRequestData contains the request body of the auth hook request.
type AuthenticateRequestData struct {
	// URL of the original request.
	URL string `json:"url,omitempty"`
	// Request headers.
	Headers map[string]string `json:"headers"`
	// Raw request body.
	Request json.RawMessage `json:"request"`
}

// HasuraV2PostRequestBody holds the original body of the request.
// It's available in [Hasura GraphQL Engine v2](https://hasura.io/docs/2.0/auth/authentication/webhook/#post-request-example) only.
//
// [Hasura GraphQL Engine v2](https://hasura.io/docs/2.0/auth/authentication/webhook/#post-request-example)
type HasuraV2PostRequestBody struct {
	Variables     map[string]any `json:"variables"`
	OperationName string         `json:"operationName,omitempty"`
	Query         string         `json:"query"`
}

// AuthenticatedOutput represents the authenticated output and authenticator metadata.
type AuthenticatedOutput struct {
	ID               string
	Mode             AuthMode
	SessionVariables map[string]any
}

// Authenticator abstracts an authenticator struct for the Authenticate method.
type Authenticator interface {
	// Authenticate validates and authenticates the token from the auth webhook request.
	Authenticate(ctx context.Context, body *AuthenticateRequestData) (AuthenticatedOutput, error)
}

// RelyAuthenticator abstracts the authenticator for the auth webhook.
type RelyAuthenticator interface {
	Authenticator

	// GetMode returns the auth mode of the current authenticator.
	Mode() AuthMode
	// Close handles the resources cleaning.
	Close() error
}

// RelyAuthDefinitionInterface abstracts the interface of an auth mode definition.
type RelyAuthDefinitionInterface interface {
	goutils.IsZeroer

	// GetMode returns the auth mode of the current config.
	GetMode() AuthMode
	// Validate if the current instance is valid.
	Validate() error
}

// RelyAuthenticatorOptions define common options for the authenticator.
type RelyAuthenticatorOptions struct {
	CustomEnvGetter  func(ctx context.Context) goenvconf.GetEnvFunc
	Logger           *slog.Logger
	HTTPClient       *gohttpc.Client
	CustomAttributes []attribute.KeyValue
	// Prefix is used to create unique JWKS registration keys, allowing multiple authenticators
	// to register the same JWKS URL independently.
	Prefix string
}

// NewRelyAuthenticatorOptions creates a new [RelyAuthenticatorOptions] instance.
func NewRelyAuthenticatorOptions(options ...RelyAuthenticatorOption) RelyAuthenticatorOptions {
	result := RelyAuthenticatorOptions{
		CustomEnvGetter: goenvconf.OSEnvGetter,
		Logger:          slog.Default(),
	}

	for _, opt := range options {
		opt(&result)
	}

	return result
}

// GetEnvFunc return the get-env function. Default is OS environment.
func (rao RelyAuthenticatorOptions) GetEnvFunc(ctx context.Context) goenvconf.GetEnvFunc {
	if rao.CustomEnvGetter == nil {
		return goenvconf.GetOSEnv
	}

	return rao.CustomEnvGetter(ctx)
}

// RelyAuthenticatorOption abstracts a function to modify [RelyAuthenticatorOptions].
type RelyAuthenticatorOption func(*RelyAuthenticatorOptions)

// WithLogger sets the logger to auth manager options.
func WithLogger(logger *slog.Logger) RelyAuthenticatorOption {
	return func(ramo *RelyAuthenticatorOptions) {
		ramo.Logger = logger
	}
}

// WithHTTPClient sets the HTTP client to auth manager options.
func WithHTTPClient(client *gohttpc.Client) RelyAuthenticatorOption {
	return func(ramo *RelyAuthenticatorOptions) {
		ramo.HTTPClient = client
	}
}

// WithPrefix sets the prefix to auth manager options.
func WithPrefix(prefix string) RelyAuthenticatorOption {
	return func(ramo *RelyAuthenticatorOptions) {
		ramo.Prefix = prefix
	}
}

// WithCustomAttributes sets custom trace and metrics attributes to auth manager options.
func WithCustomAttributes(attrs []attribute.KeyValue) RelyAuthenticatorOption {
	return func(ramo *RelyAuthenticatorOptions) {
		ramo.CustomAttributes = attrs
	}
}

// WithCustomEnvGetter returns a function to set the GetEnvFunc getter to [RelyAuthenticatorOptions].
func WithCustomEnvGetter(
	getter func(ctx context.Context) goenvconf.GetEnvFunc,
) RelyAuthenticatorOption {
	return func(ramo *RelyAuthenticatorOptions) {
		if getter == nil {
			return
		}

		ramo.CustomEnvGetter = getter
	}
}

// RelyAuthentication is the wrapper of [RelyAuthenticator] with extra security rules.
type RelyAuthentication struct {
	RelyAuthenticator

	SecurityRules *RelyAuthSecurityRules
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (ra *RelyAuthentication) Authenticate(
	ctx context.Context,
	body *AuthenticateRequestData,
) (AuthenticatedOutput, error) {
	if ra.SecurityRules != nil {
		err := ra.SecurityRules.Authenticate(body)
		if err != nil {
			return AuthenticatedOutput{
				Mode: ra.Mode(),
			}, err
		}
	}

	return ra.RelyAuthenticator.Authenticate(ctx, body)
}
