package webhook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hasura/goenvconf"
	"github.com/relychan/gotransform/jmes"
	"github.com/relychan/goutils/httpheader"
)

func NewCustomWebhookAuthHeadersConfig(
	input *WebhookAuthHeadersConfig,
	getEnvFunc goenvconf.GetEnvFunc,
) (*CustomWebhookAuthHeadersConfig, error) {
	if input == nil {
		return &CustomWebhookAuthHeadersConfig{}, nil
	}

	result := CustomWebhookAuthHeadersConfig{}

	if input.Forward != nil {
		forward := input.Forward.Map(strings.ToLower)
		result.Forward = &forward
	}

	additional, err := jmes.EvaluateObjectFieldMappingStringEntries(input.Additional, getEnvFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate additional headers: %w", err)
	}

	result.Additional = additional

	return &result, nil
}

func decodeResponseJSON(resp *http.Response, value any) error {
	err := json.NewDecoder(resp.Body).Decode(value)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return ErrResponseBodyRequired
		}

		ct := resp.Header.Get(httpheader.ContentType)

		if strings.HasPrefix(ct, httpheader.ContentTypeJSON) {
			return fmt.Errorf(
				"got Content-Type = application/json, but could not unmarshal as JSON: %w",
				err,
			)
		}

		return fmt.Errorf("failed to decode session variables: %w", err)
	}

	return nil
}
