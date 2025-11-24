// Package authmode defines common types and utilities for auth modes.
package authmode

import (
	"context"
	"encoding/json"
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
	SessionVariables map[string]any
}

// RelyAuthenticator abstracts the authenticator for the auth webhook.
type RelyAuthenticator interface {
	// GetMode returns the auth mode of the current authenticator.
	Mode() AuthMode
	// Authenticate validates and authenticates the token from the auth webhook request.
	Authenticate(ctx context.Context, body AuthenticateRequestData) (AuthenticatedOutput, error)
	// Reload credentials of the authenticator.
	Reload(ctx context.Context) error
	// Close handles the resources cleaning.
	Close() error
}

// RelyAuthDefinitionInterface abstracts the interface of an auth mode definition.
type RelyAuthDefinitionInterface interface {
	// GetMode returns the auth mode of the current config.
	GetMode() AuthMode
	// Validate if the current instance is valid.
	Validate() error
}
