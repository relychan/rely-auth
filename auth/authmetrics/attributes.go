package authmetrics

import (
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel/attribute"
)

var (
	// AuthStatusSuccessAttribute is the constant attribute for the success auth status.
	AuthStatusSuccessAttribute = attribute.String("auth.status", "success")
	// AuthStatusFailedAttribute is the constant attribute for the failed auth status.
	AuthStatusFailedAttribute = attribute.String("auth.status", "failed")
)

// NewAuthModeAttribute creates an auth.mode attribute.
func NewAuthModeAttribute(authMode authmode.AuthMode) attribute.KeyValue {
	return attribute.String("auth.mode", string(authMode))
}

// NewAuthIDAttribute creates an auth.id attribute.
func NewAuthIDAttribute(id string) attribute.KeyValue {
	return attribute.String("auth.id", id)
}
