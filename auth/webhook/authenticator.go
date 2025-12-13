// Package webhook implements the webhook auth mode
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	"github.com/relychan/gohttpc"
	"github.com/relychan/gohttpc/httpconfig"
	"github.com/relychan/gotransform"
	"github.com/relychan/goutils"
	"github.com/relychan/goutils/httpheader"
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// WebhookAuthenticator implements the authenticator with API key.
type WebhookAuthenticator struct {
	config     *RelyAuthWebhookConfig
	httpClient *gohttpc.Client
	url        string

	customRequest  customWebhookRequestConfig
	customResponse customWebhookResponseConfig
}

var tracer = otel.Tracer("rely-auth/auth/webhook")

var _ authmode.RelyAuthenticator = (*WebhookAuthenticator)(nil)

// NewWebhookAuthenticator creates a webhook authenticator instance.
func NewWebhookAuthenticator(
	ctx context.Context,
	config *RelyAuthWebhookConfig,
	opts ...gohttpc.ClientOption,
) (*WebhookAuthenticator, error) {
	result := &WebhookAuthenticator{
		config: config,
	}

	err := result.doReload(ctx, opts)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Mode returns the auth mode of the current authenticator.
func (*WebhookAuthenticator) Mode() authmode.AuthMode {
	return authmode.AuthModeWebhook
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (wa *WebhookAuthenticator) Authenticate(
	ctx context.Context,
	body authmode.AuthenticateRequestData,
) (authmode.AuthenticatedOutput, error) {
	ctx, span := tracer.Start(ctx, "Webhook", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	span.SetAttributes(attribute.String("auth.mode", string(wa.config.GetMode())))

	req := wa.httpClient.R(wa.config.Method, wa.url)
	result := authmode.AuthenticatedOutput{
		ID: wa.config.ID,
	}

	err := wa.transformRequest(req.Request, body)
	if err != nil {
		span.SetStatus(codes.Error, "failed to transform request")
		span.RecordError(err)

		return result, fmt.Errorf("failed to transform request: %w", err)
	}

	resp, err := req.Execute(ctx) //nolint:bodyclose
	if err != nil {
		span.SetStatus(codes.Error, "failed to execute auth webhook")
		span.RecordError(err)

		return result, err
	}

	if resp.Body == nil || resp.Body == http.NoBody {
		span.SetStatus(codes.Error, ErrResponseBodyRequired.Error())

		return result, ErrResponseBodyRequired
	}

	defer goutils.CatchWarnErrorFunc(resp.Body.Close)

	sessionVariables, err := wa.evaluateResponseBody(resp, span)

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

func (wa *WebhookAuthenticator) doReload(ctx context.Context, opts []gohttpc.ClientOption) error {
	endpoint, err := wa.config.URL.Get()
	if err != nil {
		return err
	}

	if endpoint == "" {
		return authmode.NewAuthFieldRequiredError(authmode.AuthModeWebhook, "url")
	}

	wa.url = endpoint

	err = wa.reloadCustomRequest()
	if err != nil {
		return err
	}

	if wa.config.CustomResponse != nil && wa.config.CustomResponse.Body != nil {
		body, err := gotransform.NewTransformerFromConfig(
			fmt.Sprintf("auth_webhook_%s_response_body", wa.config.ID),
			*wa.config.CustomResponse.Body,
		)
		if err != nil {
			return fmt.Errorf("failed to resolve transformed response config: %w", err)
		}

		wa.customResponse.Body = body
	}

	httpConfig := wa.config.HTTPClient
	if httpConfig == nil {
		if wa.httpClient != nil {
			return nil
		}

		httpConfig = &httpconfig.HTTPClientConfig{}
	}

	httpClient, err := httpconfig.NewClientFromConfig(ctx, httpConfig, opts...)
	if err != nil {
		return err
	}

	// close the old http client before setting the new client.
	if wa.httpClient != nil {
		_ = wa.httpClient.Close()
	}

	wa.httpClient = httpClient

	return nil
}

func (wa *WebhookAuthenticator) reloadCustomRequest() error {
	if wa.config.CustomRequest == nil {
		return nil
	}

	if wa.config.CustomRequest.Headers != nil {
		requestHeaders, err := newCustomWebhookAuthHeadersConfig(wa.config.CustomRequest.Headers)
		if err != nil {
			return err
		}

		wa.customRequest.Headers = requestHeaders
	}

	if wa.config.CustomRequest.Body != nil {
		body, err := gotransform.NewTransformerFromConfig(
			fmt.Sprintf("auth_webhook_%s_request_body", wa.config.ID),
			*wa.config.CustomRequest.Body,
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
	requestData authmode.AuthenticateRequestData,
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

	if wa.config.Method == http.MethodGet {
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
	requestData authmode.AuthenticateRequestData,
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
	span trace.Span,
) (map[string]any, error) {
	if wa.customResponse.Body == nil {
		sessionVariables := map[string]any{}

		err := decodeResponseJSON(span, resp, &sessionVariables)
		if err != nil {
			span.SetStatus(codes.Error, "failed to decode session variables")
			span.RecordError(err)

			return nil, err
		}

		span.SetStatus(codes.Ok, "")

		return sessionVariables, nil
	}

	// transform response body
	var responseBody any

	err := decodeResponseJSON(span, resp, &responseBody)
	if err != nil {
		span.SetStatus(codes.Error, "failed to decode response body to transform")
		span.RecordError(err)

		return nil, err
	}

	responseVariables := map[string]any{
		"headers": goutils.ExtractHeaders(resp.Header),
		"body":    responseBody,
	}

	newBody, err := wa.customResponse.Body.Transform(responseVariables)
	if err != nil {
		span.SetStatus(codes.Error, "failed to transform response body")
		span.RecordError(err)

		return nil, fmt.Errorf("failed to transform response body: %w", err)
	}

	sessionVariables, ok := newBody.(map[string]any)
	if !ok {
		err := fmt.Errorf(
			"%w, got: %s",
			ErrMalformedTransformedResponseBody,
			reflect.TypeOf(newBody).String(),
		)
		span.SetStatus(codes.Error, err.Error())

		return nil, err
	}

	span.SetStatus(codes.Ok, "")

	return sessionVariables, nil
}
