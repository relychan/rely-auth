package webhook

import (
	"fmt"
	"net/http"

	"github.com/hasura/goenvconf"
	"github.com/invopop/jsonschema"
	"github.com/relychan/gohttpc/httpconfig"
	"github.com/relychan/gotransform"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

// RelyAuthWebhookConfig contains the configuration schema for webhook authentication.
type RelyAuthWebhookConfig struct {
	// Unique identity of the auth config.
	// If not set, ID will be the index of the array.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`
	// Authentication mode which is always webhook.
	Mode authmode.AuthMode `json:"mode" yaml:"mode"`
	// Request method. Accept GET or POST.
	Method string `json:"method" yaml:"method"`
	// The URL of the authentication webhook.
	URL goenvconf.EnvString `json:"url" yaml:"url"`
	// Brief description of the auth config.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Configurations for request headers and transformed request body to be sent to the auth hook.
	CustomRequest *WebhookAuthCustomRequestConfig `json:"customRequest,omitempty" yaml:"customRequest,omitempty"`
	// The configuration for transforming response bodies.
	CustomResponse *WebhookAuthCustomResponseConfig `json:"customResponse,omitempty" yaml:"customResponse,omitempty"`
	// Configurations for the HTTP client.
	HTTPClient *httpconfig.HTTPClientConfig `json:"httpClient,omitempty" yaml:"httpClient,omitempty"`
}

var _ authmode.RelyAuthDefinitionInterface = (*RelyAuthWebhookConfig)(nil)

// NewRelyAuthWebhookConfig creates a new RelyAuthWebhookConfig instance.
func NewRelyAuthWebhookConfig(
	webhookURL goenvconf.EnvString,
	method string,
) *RelyAuthWebhookConfig {
	return &RelyAuthWebhookConfig{
		Mode:   authmode.AuthModeWebhook,
		URL:    webhookURL,
		Method: method,
	}
}

// Validate if the current instance is valid.
func (j RelyAuthWebhookConfig) Validate() error {
	mode := j.GetMode()

	if j.URL.IsZero() {
		return authmode.NewAuthFieldRequiredError(mode, "url")
	}

	if j.Method != http.MethodPost && j.Method != http.MethodGet {
		return fmt.Errorf("%w, got `%s`", ErrMethodNotAllowed, j.Method)
	}

	return nil
}

// GetMode get the auth mode of the current config.
func (RelyAuthWebhookConfig) GetMode() authmode.AuthMode {
	return authmode.AuthModeWebhook
}

// IsZero if the current instance is empty.
func (j RelyAuthWebhookConfig) IsZero() bool {
	return j.Mode == "" &&
		j.Method == "" &&
		j.URL.IsZero() &&
		j.Description == "" &&
		j.ID == "" &&
		(j.CustomRequest == nil || j.CustomRequest.IsZero()) &&
		(j.CustomResponse == nil || j.CustomResponse.IsZero()) &&
		(j.HTTPClient == nil || j.HTTPClient.IsZero())
}

// Equal checks if the target value is equal.
func (j RelyAuthWebhookConfig) Equal(target RelyAuthWebhookConfig) bool {
	return j.Mode == target.Mode &&
		j.Method == target.Method &&
		j.URL.Equal(target.URL) &&
		goutils.EqualPtr(j.CustomRequest, target.CustomRequest) &&
		goutils.EqualPtr(j.CustomResponse, target.CustomResponse) &&
		goutils.EqualPtr(j.HTTPClient, target.HTTPClient)
}

// JSONSchema is used to generate a custom jsonschema.
func (RelyAuthWebhookConfig) JSONSchema() *jsonschema.Schema {
	envStringRef := "#/$defs/EnvString"
	authHeadersConfigRef := "#/$defs/WebhookAuthHeadersConfig"

	commonProps := orderedmap.New[string, *jsonschema.Schema]()
	commonProps.Set("mode", &jsonschema.Schema{
		Type:        "string",
		Description: "Authentication mode which is always webhook",
		Enum:        []any{authmode.AuthModeWebhook},
	})
	commonProps.Set("description", &jsonschema.Schema{
		Type:        "string",
		Description: "Brief description of the auth config",
	})
	commonProps.Set("url", &jsonschema.Schema{
		Description: "The URL of the authentication webhook",
		Ref:         envStringRef,
	})
	commonProps.Set("httpClient", &jsonschema.Schema{
		Description: "Configurations for the HTTP client",
		Ref:         "https://raw.githubusercontent.com/relychan/gohttpc/refs/heads/main/jsonschema/gohttpc.schema.json",
	})
	commonProps.Set("customResponse", &jsonschema.Schema{
		Description: "The configuration for transforming response bodies",
		Ref:         "#/$defs/WebhookAuthCustomResponseConfig",
	})

	// get webhook properties
	getHeadersConfig := orderedmap.New[string, *jsonschema.Schema]()
	getHeadersConfig.Set("headers", &jsonschema.Schema{
		Ref: authHeadersConfigRef,
	})

	getProps := orderedmap.New[string, *jsonschema.Schema]()
	getProps.Set("method", &jsonschema.Schema{
		Type:        "string",
		Description: "GET webhook method",
		Enum:        []any{http.MethodGet},
	})
	getProps.Set("customRequest", &jsonschema.Schema{
		Description: "Configurations for request headers and transformed request body to be sent to the auth hook",
		Type:        "object",
		Properties:  getHeadersConfig,
	})

	// post webhook properties
	postWebhookConfig := orderedmap.New[string, *jsonschema.Schema]()
	postWebhookConfig.Set("headers", &jsonschema.Schema{
		Ref: authHeadersConfigRef,
	})

	postWebhookConfig.Set("body", &jsonschema.Schema{
		Ref: "https://raw.githubusercontent.com/relychan/gotransform/refs/heads/main/jsonschema/gotransform.schema.json",
	})

	postProps := orderedmap.New[string, *jsonschema.Schema]()
	postProps.Set("method", &jsonschema.Schema{
		Type:        "string",
		Description: "POST webhook method",
		Enum:        []any{http.MethodPost},
	})
	postProps.Set("customRequest", &jsonschema.Schema{
		Description: "Configurations for request headers and transformed request body to be sent to the auth hook",
		Type:        "object",
		Properties:  postWebhookConfig,
	})

	return &jsonschema.Schema{
		OneOf: []*jsonschema.Schema{
			{
				Type:       "object",
				Properties: getProps,
			},
			{
				Type:       "object",
				Properties: postProps,
			},
		},
		Type:       "object",
		Properties: commonProps,
		Required:   []string{"mode", "url", "method"},
	}
}

// WebhookAuthCustomRequestConfig represents the configuration for request headers and transformed request body to be sent to the auth hook.
type WebhookAuthCustomRequestConfig struct {
	// The configuration to transform request headers.
	Headers *WebhookAuthHeadersConfig `json:"headers,omitempty" yaml:"headers,omitempty"`
	// The configuration to transform request body.
	Body *gotransform.TemplateTransformerConfig `json:"body,omitempty"    yaml:"body,omitempty"`
}

// IsZero if the current instance is empty.
func (wa WebhookAuthCustomRequestConfig) IsZero() bool {
	return (wa.Headers == nil || wa.Headers.IsZero()) &&
		(wa.Body == nil || wa.Body.IsZero())
}

// Equal checks if the target value is equal.
func (wa WebhookAuthCustomRequestConfig) Equal(target WebhookAuthCustomRequestConfig) bool {
	return goutils.EqualPtr(wa.Headers, target.Headers) &&
		goutils.EqualPtr(wa.Body, target.Body)
}

// WebhookAuthHeadersConfig is the configuration for the headers to be sent to the auth hook.
type WebhookAuthHeadersConfig struct {
	// The headers to be forwarded from the client request.
	Forward *goutils.AllOrListString `json:"forward,omitempty" yaml:"forward,omitempty"`
	// The additional headers to be sent to the auth hook.
	Additional map[string]jmes.FieldMappingEntryStringConfig `json:"additional,omitempty" yaml:"additional,omitempty"`
}

// IsZero if the current instance is empty.
func (wa WebhookAuthHeadersConfig) IsZero() bool {
	return (wa.Forward == nil || wa.Forward.IsZero()) &&
		len(wa.Additional) == 0
}

// Equal checks if the target value is equal.
func (wa WebhookAuthHeadersConfig) Equal(target WebhookAuthHeadersConfig) bool {
	return goutils.EqualPtr(wa.Forward, target.Forward) &&
		goutils.EqualMap(wa.Additional, target.Additional, true)
}

// WebhookAuthCustomResponseConfig is the configuration for transforming response bodies.
type WebhookAuthCustomResponseConfig struct {
	// The template to transform the response body.
	Body *gotransform.TemplateTransformerConfig `json:"response,omitempty" yaml:"response,omitempty"`
}

// IsZero if the current instance is empty.
func (wa WebhookAuthCustomResponseConfig) IsZero() bool {
	return wa.Body == nil || wa.Body.IsZero()
}

// Equal checks if the target value is equal.
func (wa WebhookAuthCustomResponseConfig) Equal(target WebhookAuthCustomResponseConfig) bool {
	return goutils.EqualPtr(wa.Body, target.Body)
}
