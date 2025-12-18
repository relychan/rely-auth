// Package handler implements handler routes for auth webhooks.
package handler

import (
	"log/slog"
	"net/http"

	"github.com/hasura/gotel"
	"github.com/relychan/gohttps/httputils"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// HasuraDDNAuthHookHandler implements HTTP handlers for Hasura DDN auth webhook.
type HasuraDDNAuthHookHandler struct {
	authenticator authmode.Authenticator
}

// NewHasuraDDNAuthHookHandler creates a ddn auth hook handler instance.
func NewHasuraDDNAuthHookHandler(authenticator authmode.Authenticator) *HasuraDDNAuthHookHandler {
	return &HasuraDDNAuthHookHandler{
		authenticator: authenticator,
	}
}

// Get handles the auth hook with GET method.
func (handler *HasuraDDNAuthHookHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := trace.SpanFromContext(ctx)
	body := newAuthenticateGETBody(r)

	handler.handle(w, r, body, span)
}

// Post handles the auth hook with POST method.
func (handler *HasuraDDNAuthHookHandler) Post(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := trace.SpanFromContext(ctx)

	body, decoded := httputils.DecodeRequestBody[authmode.AuthenticateRequestData](w, r, span)
	if !decoded {
		return
	}

	handler.handle(w, r, body, span)
}

func (handler *HasuraDDNAuthHookHandler) handle(
	w http.ResponseWriter,
	r *http.Request,
	body *authmode.AuthenticateRequestData,
	span trace.Span,
) {
	ctx := r.Context()
	logger := gotel.GetRequestLogger(r)

	authResult, err := handler.authenticator.Authenticate(ctx, body)
	if err != nil {
		span.SetStatus(codes.Error, "failed to authenticate")
		span.RecordError(err)

		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	hasuraRole, ok := authResult.SessionVariables[authmode.XHasuraRole]
	if !ok || hasuraRole == nil || hasuraRole == "" {
		span.SetStatus(codes.Error, "x-hasura-role session variable is empty")

		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	err = httputils.WriteResponseJSON(w, http.StatusOK, authResult.SessionVariables)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)

		logger.Error("failed to write response", slog.String("error", err.Error()))
	}
}

func newAuthenticateGETBody(r *http.Request) *authmode.AuthenticateRequestData {
	body := authmode.AuthenticateRequestData{
		URL:     r.URL.String(),
		Headers: goutils.ExtractHeaders(r.Header),
	}

	return &body
}
