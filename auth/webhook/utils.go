package webhook

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/relychan/gotransform/jmes"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"resty.dev/v3"
)

func newCustomWebhookAuthHeadersConfig(
	input *WebhookAuthHeadersConfig,
) (*customWebhookAuthHeadersConfig, error) {
	if input == nil {
		return &customWebhookAuthHeadersConfig{}, nil
	}

	result := customWebhookAuthHeadersConfig{
		Forward: input.Forward,
	}

	additional, err := jmes.EvaluateObjectFieldMappingStringEntries(input.Additional)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate additional headers: %w", err)
	}

	result.Additional = additional

	return &result, nil
}

func decodeResponseJSON(span trace.Span, resp *resty.Response, value any) error {
	err := json.NewDecoder(resp.Body).Decode(value)
	if err != nil {
		span.SetStatus(codes.Error, "failed to decode session variables")
		span.RecordError(err)

		ct := resp.Header().Get("Content-Type")

		if strings.HasPrefix(ct, "application/json") {
			return fmt.Errorf(
				"got Content-Type = application/json, but could not unmarshal as JSON: %w",
				err,
			)
		}

		return fmt.Errorf("failed to decode session variables: %w", err)
	}

	return nil
}
