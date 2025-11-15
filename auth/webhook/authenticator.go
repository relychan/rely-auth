// Package webhook implements the webhook auth mode
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/relychan/gohttps"
	"github.com/relychan/gorestly"
	"github.com/relychan/gotransform"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"resty.dev/v3"
)

// WebhookAuthenticator implements the authenticator with API key.
type WebhookAuthenticator struct {
	config     RelyAuthWebhookConfig
	httpClient *resty.Client
	url        string
	mu         sync.RWMutex

	customRequest  customWebhookRequestConfig
	customResponse customWebhookResponseConfig
}

var tracer = otel.Tracer("rely-auth/auth/webhook")

var _ authmode.RelyAuthenticator = (*WebhookAuthenticator)(nil)

// NewWebhookAuthenticator creates a webhook authenticator instance.
func NewWebhookAuthenticator(config RelyAuthWebhookConfig) (*WebhookAuthenticator, error) {
	result := &WebhookAuthenticator{
		config: config,
	}

	err := result.doReload()
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetMode returns the auth mode of the current authenticator.
func (*WebhookAuthenticator) GetMode() authmode.AuthMode {
	return authmode.AuthModeWebhook
}

// Authenticate validates and authenticates the token from the auth webhook request.
func (wa *WebhookAuthenticator) Authenticate(
	ctx context.Context,
	body authmode.AuthenticateRequestData,
) (map[string]any, error) {
	ctx, span := tracer.Start(ctx, "Authenticate", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	span.SetAttributes(attribute.String("auth.mode", string(wa.config.GetMode())))

	wa.mu.RLock()
	req := wa.httpClient.R().SetContext(ctx)
	endpoint := wa.url
	wa.mu.RUnlock()

	err := wa.transformRequest(req, body)
	if err != nil {
		span.SetStatus(codes.Error, "failed to transform request")
		span.RecordError(err)

		return nil, fmt.Errorf("failed to transform request: %w", err)
	}

	resp, err := req.Execute(wa.config.Method, endpoint)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())

		return nil, fmt.Errorf("failed to execute auth webhook: %w", err)
	}

	defer goutils.CatchWarnErrorFunc(resp.Body.Close)

	if resp.StatusCode() != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			span.SetStatus(codes.Error, "unable to read response body")
			span.RecordError(err)

			return nil, fmt.Errorf("unable to read response body: %w", err)
		}

		span.SetAttributes(
			attribute.Int("auth.webhook.response.status", resp.StatusCode()),
			attribute.String("auth.webhook.response.body", string(body)),
		)

		span.SetStatus(codes.Error, "authentication failed")

		return nil, gohttps.NewUnauthorizedError()
	}

	sessionVariables := map[string]any{}

	if len(wa.customResponse.Body) == 0 {
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

	err = decodeResponseJSON(span, resp, &responseBody)
	if err != nil {
		span.SetStatus(codes.Error, "failed to decode response body to transform")
		span.RecordError(err)

		return nil, err
	}

	responseVariables := map[string]any{
		"headers": goutils.ExtractHeaders(resp.Header()),
		"body":    responseBody,
	}

	for key, field := range wa.customResponse.Body {
		fieldValue, err := field.Evaluate(responseVariables)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}

		sessionVariables[key] = fieldValue
	}

	span.SetStatus(codes.Ok, "")

	return sessionVariables, nil
}

// Close handles the resources cleaning.
func (wa *WebhookAuthenticator) Close() error {
	if wa.httpClient != nil {
		return wa.httpClient.Close()
	}

	return nil
}

// Reload credentials of the authenticator.
func (wa *WebhookAuthenticator) Reload(_ context.Context) error {
	wa.mu.Lock()
	defer wa.mu.Unlock()

	return wa.doReload()
}

func (wa *WebhookAuthenticator) doReload() error {
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

	if wa.config.CustomResponse != nil {
		responseMappingFields, err := jmes.EvaluateObjectFieldMappingEntries(
			wa.config.CustomResponse.Body,
		)
		if err != nil {
			return fmt.Errorf("failed to resolve transformed response config: %w", err)
		}

		wa.customResponse.Body = responseMappingFields
	}

	httpConfig := wa.config.HTTPClient
	if httpConfig == nil {
		httpConfig = &gorestly.RestyConfig{}
	}

	httpClient, err := gorestly.NewClientFromConfig(
		*httpConfig,
		gorestly.WithLogger(slog.With("type", "authenticator").
			With(slog.String("mode", string(authmode.AuthModeWebhook)))),
		gorestly.WithTracer(tracer),
	)
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
		body, err := gotransform.NewTransformerFromConfig("webhook", *wa.config.CustomRequest.Body)
		if err != nil {
			return err
		}

		wa.customRequest.Body = body
	}

	return nil
}

func (wa *WebhookAuthenticator) transformRequest(
	req *resty.Request,
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

	for key, additional := range wa.customRequest.Headers.Additional {
		if additional.Path != nil {
			headerValue, err := additional.EvaluateString(originalRequest)
			if err != nil {
				return fmt.Errorf("failed to evaluate additional header: %w", err)
			}

			if headerValue != nil {
				req.SetHeader(key, *headerValue)

				continue
			}
		}

		if additional.Default != nil {
			req.SetHeader(key, *additional.Default)
		}
	}

	// forwarded headers will have the higher priority
	wa.forwardRequestHeaders(req, requestData)

	if wa.config.Method == http.MethodGet {
		return nil
	}

	req.Header.Set("Content-Type", gohttps.ContentTypeJSON)

	newBody, err := wa.customRequest.Body.Transform(originalRequest)
	if err != nil {
		return fmt.Errorf("failed to transform request body: %w", err)
	}

	req.SetBody(newBody)

	return nil
}

func (wa *WebhookAuthenticator) forwardRequestHeaders(
	req *resty.Request,
	requestData authmode.AuthenticateRequestData,
) {
	if wa.customRequest.Headers == nil || wa.customRequest.Headers.Forward == nil {
		return
	}

	if wa.customRequest.Headers.Forward.IsAll() {
		for key, header := range requestData.Headers {
			if !excludedHeadersFromGET[key] {
				req.SetHeader(key, header)
			}
		}
	} else {
		for _, name := range wa.customRequest.Headers.Forward.List() {
			value, ok := requestData.Headers[name]
			if ok {
				req.SetHeader(name, value)
			}
		}
	}
}
