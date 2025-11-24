package auth

import (
	"github.com/hasura/gotel"
	"go.opentelemetry.io/otel/attribute"
)

var (
	tracer                     = gotel.NewTracer("rely-auth")
	authStatusSuccessAttribute = attribute.String("auth.status", "success")
	authStatusFailedAttribute  = attribute.String("auth.status", "failed")
)
