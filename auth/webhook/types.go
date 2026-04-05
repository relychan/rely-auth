// Copyright 2026 RelyChan Pte. Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

// CustomWebhookRequestConfig represents a custom webhook request config.
type CustomWebhookRequestConfig struct {
	Headers *CustomWebhookAuthHeadersConfig
	Body    gotransform.TemplateTransformer
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
