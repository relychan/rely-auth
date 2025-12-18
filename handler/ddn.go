// Package handler implements handler routes for auth webhooks.
package handler

import (
	"log/slog"
	"net/http"

	"github.com/hasura/gotel"
	"github.com/relychan/gohttps/httputils"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth"
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// HasuraDDNAuthHookHandler implements HTTP handlers for Hasura DDN auth webhook.
type HasuraDDNAuthHookHandler struct {
	authManager *auth.RelyAuthManager
}

// NewHasuraDDNAuthHookHandler creates a ddn auth hook handler instance.
func NewHasuraDDNAuthHookHandler(authManager *auth.RelyAuthManager) *HasuraDDNAuthHookHandler {
	return &HasuraDDNAuthHookHandler{
		authManager: authManager,
	}
}

// Get handles the auth hook with GET method.
func (handler *HasuraDDNAuthHookHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := trace.SpanFromContext(ctx)
	logger := gotel.GetRequestLogger(r)

	body := newAuthenticateGETBody(r)

	authOutput, err := handler.authManager.Authenticate(ctx, *body)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	err = httputils.WriteResponseJSON(w, http.StatusOK, authOutput.SessionVariables)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)

		logger.Error("failed to write response", slog.String("error", err.Error()))
	}
}

// Post handles the auth hook with POST method.
func (handler *HasuraDDNAuthHookHandler) Post(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := trace.SpanFromContext(ctx)
	logger := gotel.GetRequestLogger(r)

	body, decoded := httputils.DecodeRequestBody[authmode.AuthenticateRequestData](w, r, span)
	if !decoded {
		return
	}

	authResult, err := handler.authManager.Authenticate(ctx, *body)
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
