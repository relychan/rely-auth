package webhook

import (
	"fmt"
	"net/http"

	"github.com/hasura/goenvconf"
	"github.com/relychan/gorestly"
	"github.com/relychan/gotransform"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
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
	HTTPClient *gorestly.RestyConfig `json:"httpClient,omitempty" yaml:"httpClient,omitempty"`
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
		return fmt.Errorf("%w, got `%s`", ErrWebhookAuthMethodNotAllowed, j.Method)
	}

	return nil
}

// GetMode get the auth mode of the current config.
func (RelyAuthWebhookConfig) GetMode() authmode.AuthMode {
	return authmode.AuthModeWebhook
}

// WebhookAuthCustomRequestConfig represents the configuration for request headers and transformed request body to be sent to the auth hook.
type WebhookAuthCustomRequestConfig struct {
	Headers *WebhookAuthHeadersConfig              `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body    *gotransform.TemplateTransformerConfig `json:"body,omitempty"    yaml:"body,omitempty"`
}

// WebhookAuthHeadersConfig is the configuration for the headers to be sent to the auth hook.
type WebhookAuthHeadersConfig struct {
	// The headers to be forwarded from the client request.
	Forward *goutils.AllOrListString `json:"forward,omitempty" yaml:"forward,omitempty"`
	// The additional headers to be sent to the auth hook.
	Additional map[string]jmes.FieldMappingEntryStringConfig `json:"additional,omitempty" yaml:"additional,omitempty"`
}

// WebhookAuthCustomResponseConfig is the configuration for transforming response bodies.
type WebhookAuthCustomResponseConfig struct {
	Body map[string]jmes.FieldMappingEntryConfig `json:"response,omitempty" yaml:"response,omitempty"`
}
