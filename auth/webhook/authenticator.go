// Package webhook implements the webhook auth mode
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	"github.com/hasura/goenvconf"
	"github.com/relychan/gohttpc"
	"github.com/relychan/gohttpc/httpconfig"
	"github.com/relychan/gotransform"
	"github.com/relychan/goutils"
	"github.com/relychan/goutils/httpheader"
	"github.com/relychan/rely-auth/auth/authmode"
)

// WebhookAuthenticator implements the authenticator with API key.
type WebhookAuthenticator struct {
	id         string
	method     string
	httpClient *gohttpc.Client
	url        string

	customRequest  CustomWebhookRequestConfig
	customResponse CustomWebhookResponseConfig
}

var _ authmode.RelyAuthenticator = (*WebhookAuthenticator)(nil)

// NewWebhookAuthenticator creates a webhook authenticator instance.
func NewWebhookAuthenticator(
	ctx context.Context,
	config *RelyAuthWebhookConfig,
	opts authmode.RelyAuthenticatorOptions,
) (*WebhookAuthenticator, error) {
	result := &WebhookAuthenticator{
		id:     config.ID,
		method: config.Method,
	}

	err := result.init(ctx, config, opts)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Mode returns the auth mode of the current authenticator.
func (*WebhookAuthenticator) Mode() authmode.AuthMode {
	return authmode.AuthModeWebhook
}

// Equal checks if the target value is equal.
func (wa WebhookAuthenticator) Equal(target WebhookAuthenticator) bool {
	return wa.id == target.id &&
		wa.method == target.method &&
		wa.url == target.url &&
		wa.customRequest.Equal(target.customRequest) &&
		wa.customResponse.Equal(target.customResponse) &&
		wa.httpClient == target.httpClient
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (wa *WebhookAuthenticator) Authenticate(
	ctx context.Context,
	body *authmode.AuthenticateRequestData,
) (authmode.AuthenticatedOutput, error) {
	req := wa.httpClient.R(wa.method, wa.url)
	result := authmode.AuthenticatedOutput{
		ID:   wa.id,
		Mode: authmode.AuthModeWebhook,
	}

	err := wa.transformRequest(req.Request, body)
	if err != nil {
		return result, fmt.Errorf("failed to transform request: %w", err)
	}

	resp, err := req.Execute(ctx) //nolint:bodyclose
	if err != nil {
		return result, fmt.Errorf("failed to execute auth webhook: %w", err)
	}

	if resp.Body == nil || resp.Body == http.NoBody {
		return result, ErrResponseBodyRequired
	}

	defer goutils.CatchWarnErrorFunc(resp.Body.Close)

	sessionVariables, err := wa.evaluateResponseBody(resp)

	result.SessionVariables = sessionVariables

	return result, err
}

// Close handles the resources cleaning.
func (wa *WebhookAuthenticator) Close() error {
	if wa.httpClient != nil {
		return wa.httpClient.Close()
	}

	return nil
}

// Reload credentials of the authenticator.
func (*WebhookAuthenticator) Reload(_ context.Context) error {
	return nil
}

func (wa *WebhookAuthenticator) init(
	ctx context.Context,
	config *RelyAuthWebhookConfig,
	options authmode.RelyAuthenticatorOptions,
) error {
	getEnvFunc := options.GetEnvFunc(ctx)

	endpoint, err := config.URL.GetCustom(getEnvFunc)
	if err != nil {
		return err
	}

	if endpoint == "" {
		return authmode.NewAuthFieldRequiredError(authmode.AuthModeWebhook, "url")
	}

	wa.url = endpoint

	err = wa.initCustomRequest(config, getEnvFunc)
	if err != nil {
		return err
	}

	if config.CustomResponse != nil && config.CustomResponse.Body != nil {
		body, err := gotransform.NewTransformerFromConfig(
			fmt.Sprintf("auth_webhook_%s_response_body", config.ID),
			*config.CustomResponse.Body,
			getEnvFunc,
		)
		if err != nil {
			return fmt.Errorf("failed to resolve transformed response config: %w", err)
		}

		wa.customResponse.Body = body
	}

	httpConfig := config.HTTPClient
	if httpConfig == nil {
		httpConfig = &httpconfig.HTTPClientConfig{}
	}

	httpClient, err := httpconfig.NewClientFromConfig(
		ctx,
		httpConfig,
		gohttpc.WithCustomEnvGetter(options.CustomEnvGetter),
	)
	if err != nil {
		return err
	}

	wa.httpClient = httpClient

	return nil
}

func (wa *WebhookAuthenticator) initCustomRequest(
	config *RelyAuthWebhookConfig,
	getEnvFunc goenvconf.GetEnvFunc,
) error {
	if config.CustomRequest == nil {
		return nil
	}

	if config.CustomRequest.Headers != nil {
		requestHeaders, err := NewCustomWebhookAuthHeadersConfig(
			config.CustomRequest.Headers,
			getEnvFunc,
		)
		if err != nil {
			return err
		}

		wa.customRequest.Headers = requestHeaders
	}

	if config.CustomRequest.Body != nil {
		body, err := gotransform.NewTransformerFromConfig(
			fmt.Sprintf("auth_webhook_%s_request_body", config.ID),
			*config.CustomRequest.Body,
			getEnvFunc,
		)
		if err != nil {
			return err
		}

		wa.customRequest.Body = body
	}

	return nil
}

func (wa *WebhookAuthenticator) transformRequest(
	req *gohttpc.Request,
	requestData *authmode.AuthenticateRequestData,
) error {
	// original request body
	originalRequest := map[string]any{
		"url":     requestData.URL,
		"headers": requestData.Headers,
		"body":    nil,
	}

	if len(requestData.Request) > 0 {
		var body any

		err := json.Unmarshal(requestData.Request, &body)
		if err != nil {
			return err
		}

		originalRequest["body"] = body
	}

	if wa.customRequest.Headers != nil {
		for key, additional := range wa.customRequest.Headers.Additional {
			if additional.Path != nil {
				headerValue, err := additional.EvaluateString(originalRequest)
				if err != nil {
					return fmt.Errorf("failed to evaluate additional header: %w", err)
				}

				if headerValue != nil {
					req.Header().Set(key, *headerValue)

					continue
				}
			}

			if additional.Default != nil {
				req.Header().Set(key, *additional.Default)
			}
		}
	}

	// forwarded headers will have the higher priority
	wa.forwardRequestHeaders(req, requestData)

	if wa.method == http.MethodGet {
		return nil
	}

	req.Header().Set(httpheader.ContentType, httpheader.ContentTypeJSON)

	newBody, err := wa.customRequest.Body.Transform(originalRequest)
	if err != nil {
		return fmt.Errorf("failed to transform request body: %w", err)
	}

	bodyBuf := new(bytes.Buffer)

	enc := json.NewEncoder(bodyBuf)
	enc.SetEscapeHTML(false)

	err = enc.Encode(newBody)
	if err != nil {
		return fmt.Errorf("failed to transform request body: %w", err)
	}

	req.SetBody(bodyBuf)

	return nil
}

func (wa *WebhookAuthenticator) forwardRequestHeaders(
	req *gohttpc.Request,
	requestData *authmode.AuthenticateRequestData,
) {
	if wa.customRequest.Headers == nil || wa.customRequest.Headers.Forward == nil {
		return
	}

	if wa.customRequest.Headers.Forward.IsAll() {
		for key, header := range requestData.Headers {
			if !excludedHeadersFromGET[key] {
				req.Header().Set(key, header)
			}
		}
	} else {
		for _, name := range wa.customRequest.Headers.Forward.List() {
			value, ok := requestData.Headers[name]
			if ok {
				req.Header().Set(name, value)
			}
		}
	}
}

func (wa *WebhookAuthenticator) evaluateResponseBody(
	resp *http.Response,
) (map[string]any, error) {
	if wa.customResponse.Body == nil {
		sessionVariables := map[string]any{}
		err := decodeResponseJSON(resp, &sessionVariables)

		return sessionVariables, err
	}

	// transform response body
	var responseBody any

	err := decodeResponseJSON(resp, &responseBody)
	if err != nil {
		return nil, err
	}

	responseVariables := map[string]any{
		"headers": goutils.ExtractHeaders(resp.Header),
		"body":    responseBody,
	}

	newBody, err := wa.customResponse.Body.Transform(responseVariables)
	if err != nil {
		return nil, fmt.Errorf("failed to transform response body: %w", err)
	}

	sessionVariables, ok := newBody.(map[string]any)
	if !ok {
		err := fmt.Errorf(
			"%w, got: %s",
			ErrMalformedTransformedResponseBody,
			reflect.TypeOf(newBody).String(),
		)

		return nil, err
	}

	return sessionVariables, nil
}
