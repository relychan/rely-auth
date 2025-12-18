package authmetrics

import "go.opentelemetry.io/otel/attribute"

var (
	// AuthStatusSuccessAttribute is the constant attribute for the success auth status.
	AuthStatusSuccessAttribute = attribute.String("auth.status", "success")
	// AuthStatusFailedAttribute is the constant attribute for the failed auth status.
	AuthStatusFailedAttribute = attribute.String("auth.status", "failed")
)
