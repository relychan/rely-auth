package handler

import (
	"log/slog"
	"net/http"

	"github.com/hasura/gotel"
	"github.com/relychan/gohttps"
	"github.com/relychan/rely-auth/auth"
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// HasuraGraphQLEngineAuthHookHandler implements an HTTP handler for auth webhook of Hasura GraphQL Engine v1 and v2.
type HasuraGraphQLEngineAuthHookHandler struct {
	authManager *auth.RelyAuthManager
}

// NewHasuraGraphQLEngineAuthHookHandler creates a auth hook handler for Hasura GraphQL Engine v1 and v2.
func NewHasuraGraphQLEngineAuthHookHandler(
	authManager *auth.RelyAuthManager,
) *HasuraGraphQLEngineAuthHookHandler {
	return &HasuraGraphQLEngineAuthHookHandler{
		authManager: authManager,
	}
}

// Get handles the auth hook with GET method.
func (handler *HasuraGraphQLEngineAuthHookHandler) Get(w http.ResponseWriter, r *http.Request) {
	span := trace.SpanFromContext(r.Context())
	body := newAuthenticateGETBody(r)

	handler.handle(w, r, span, body)
}

// Post handles the auth hook with POST method.
func (handler *HasuraGraphQLEngineAuthHookHandler) Post(w http.ResponseWriter, r *http.Request) {
	span := trace.SpanFromContext(r.Context())

	body, decoded := gohttps.DecodeRequestBody[authmode.AuthenticateRequestData](w, r, span)
	if !decoded {
		return
	}

	handler.handle(w, r, span, body)
}

func (handler *HasuraGraphQLEngineAuthHookHandler) handle(
	w http.ResponseWriter,
	r *http.Request,
	span trace.Span,
	body *authmode.AuthenticateRequestData,
) {
	logger := gotel.GetRequestLogger(r)

	sessionVariables, err := handler.authManager.Authenticate(r.Context(), *body)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)

		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	serializedVariables, err := authmode.SerializeSessionVariablesHasuraGraphQLEngine(
		sessionVariables,
	)
	if err != nil {
		span.SetStatus(codes.Error, "failed to serialize session variables")
		span.RecordError(err)

		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	err = gohttps.WriteResponseJSON(w, http.StatusOK, serializedVariables)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)

		logger.Error("failed to write response", slog.String("error", err.Error()))
	}
}
