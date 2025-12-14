package webhook

import (
	"errors"

	"github.com/relychan/gotransform"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/goutils"
)

var (
	// ErrMethodNotAllowed occurs when the method is neither GET nor POST.
	ErrMethodNotAllowed = errors.New("webhook mode must be one of GET or POST")

	// ErrResponseBodyRequired occurs when the response body have no content.
	ErrResponseBodyRequired = errors.New("response body must have content")

	// ErrMalformedTransformedResponseBody occurs when the transformed response body is malformed.
	ErrMalformedTransformedResponseBody = errors.New("malformed response body. Expected a map")
)

// CustomWebhookResponseConfig represents a custom webhook response config.
type CustomWebhookResponseConfig struct {
	Body gotransform.TemplateTransformer
}

// Equal checks if the target value is equal.
func (cwr CustomWebhookResponseConfig) Equal(target CustomWebhookResponseConfig) bool {
	return gotransform.EqualTemplateTransformer(cwr.Body, target.Body)
}

// CustomWebhookRequestConfig represents a custom webhook request config.
type CustomWebhookRequestConfig struct {
	Headers *CustomWebhookAuthHeadersConfig
	Body    gotransform.TemplateTransformer
}

// Equal checks if the target value is equal.
func (cwr CustomWebhookRequestConfig) Equal(target CustomWebhookRequestConfig) bool {
	return gotransform.EqualTemplateTransformer(cwr.Body, target.Body) &&
		goutils.EqualPtr(cwr.Headers, target.Headers)
}

// CustomWebhookAuthHeadersConfig represents a custom webhook auth header config.
type CustomWebhookAuthHeadersConfig struct {
	// The headers to be forwarded from the client request.
	Forward *goutils.AllOrListString
	// The additional headers to be sent to the auth hook.
	Additional map[string]jmes.FieldMappingEntryString
}

// Equal checks if the target value is equal.
func (cwr CustomWebhookAuthHeadersConfig) Equal(target CustomWebhookAuthHeadersConfig) bool {
	return goutils.EqualPtr(cwr.Forward, target.Forward) &&
		goutils.EqualMap(cwr.Additional, target.Additional, true)
}

// If the webhook uses GET, the following headers will be ignored.
var excludedHeadersFromGET = map[string]bool{
	"content-length":  true,
	"content-type":    true,
	"content-md5":     true,
	"user-agent":      true,
	"host":            true,
	"origin":          true,
	"referer":         true,
	"accept":          true,
	"accept-encoding": true,
	"accept-language": true,
	"accept-datetime": true,
	"cache-control":   true,
	"connection":      true,
	"dnt":             true,
}
