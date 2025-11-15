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
)

type customWebhookResponseConfig struct {
	Body map[string]jmes.FieldMappingEntry
}

type customWebhookRequestConfig struct {
	Headers *customWebhookAuthHeadersConfig
	Body    gotransform.TemplateTransformer
}

type customWebhookAuthHeadersConfig struct {
	// The headers to be forwarded from the client request.
	Forward *goutils.AllOrListString
	// The additional headers to be sent to the auth hook.
	Additional map[string]jmes.FieldMappingEntryString
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
