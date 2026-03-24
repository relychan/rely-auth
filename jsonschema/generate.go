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

// Package main generates JSON schemas for the rely-auth config.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"

	"github.com/relychan/goutils"
	"github.com/relychan/jsonschema"
	"github.com/relychan/rely-auth/auth"
	"github.com/relychan/rely-auth/auth/apikey"
	"github.com/relychan/rely-auth/auth/authmode"
	"github.com/relychan/rely-auth/auth/jwt"
	"github.com/relychan/rely-auth/auth/noauth"
	"github.com/relychan/rely-auth/auth/webhook"
)

func main() {
	err := jsonSchemaConfiguration()
	if err != nil {
		panic(fmt.Errorf("failed to write jsonschema for RelyAuthConfig: %w", err))
	}
}

func jsonSchemaConfiguration() error {
	r := new(jsonschema.Reflector)

	for _, name := range []string{"/auth", "/auth/apikey", "/auth/jwt", "/auth/noauth", "/auth/webhook"} {
		err := r.AddGoComments(
			"github.com/relychan/rely-auth"+name,
			".."+name,
			jsonschema.WithFullComment(),
		)
		if err != nil {
			return err
		}
	}

	reflectSchema := r.Reflect(auth.RelyAuthConfig{})

	for _, externalType := range []any{
		noauth.RelyAuthNoAuthConfig{},
		apikey.RelyAuthAPIKeyConfig{},
		jwt.RelyAuthJWTConfig{},
		webhook.RelyAuthWebhookConfig{},
		webhook.WebhookAuthHeadersConfig{},
		webhook.WebhookAuthCustomResponseConfig{},
		authmode.RelyAuthSecurityRulesConfig{},
	} {
		externalSchema := r.Reflect(externalType)

		for key, def := range externalSchema.Definitions {
			if _, ok := reflectSchema.Definitions[key]; !ok {
				reflectSchema.Definitions[key] = def
			}
		}
	}

	// custom schema types
	reflectSchema.Definitions["JWTSignatureAlgorithm"] = &jsonschema.Schema{
		Type:        "string",
		Description: "Specifies the cryptographic signing algorithm which is used to sign the JWTs. This is required only if you are using the key property in the config.",
		Enum:        goutils.ToAnySlice(jwt.GetSupportedSignatureAlgorithms()),
	}

	remoteSchemas, err := downloadRemoteSchemas()
	if err != nil {
		return err
	}

	for _, rc := range remoteSchemas {
		maps.Copy(reflectSchema.Definitions, rc.Definitions)
	}

	for _, key := range []string{
		"RelyAuthNoAuthConfig",
		"RelyAuthAPIKeyConfig",
		"RelyAuthJWTConfig",
		"RelyAuthWebhookConfig",
	} {
		reflectSchema.Definitions[key].Properties.Set("securityRules", &jsonschema.Schema{
			Description: "Configurations for extra security rules",
			Ref:         "#/$defs/RelyAuthSecurityRulesConfig",
		})
	}

	reflectSchema.Definitions["AllOrListString"] = &jsonschema.Schema{
		OneOf: []*jsonschema.Schema{
			{
				Type:        "string",
				Enum:        []any{"*"},
				Description: "The wildcard string means all values are allowed",
			},
			{
				Type:        "array",
				Description: "An explicit list of allowed string values",
				Items: &jsonschema.Schema{
					Type: "string",
				},
			},
		},
	}

	schemaBytes, err := json.MarshalIndent(reflectSchema, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile("auth.schema.json", schemaBytes, 0o644) //nolint:gosec
}

func downloadRemoteSchemas() ([]*jsonschema.Schema, error) {
	fileURLs := []string{
		"https://raw.githubusercontent.com/relychan/gohttpc/refs/heads/main/jsonschema/gohttpc.schema.json",
		"https://raw.githubusercontent.com/relychan/gotransform/refs/heads/main/jsonschema/gotransform.schema.json",
	}

	results := make([]*jsonschema.Schema, 0, len(fileURLs))

	for _, fileURL := range fileURLs {
		rawResp, err := http.Get(fileURL) //nolint:bodyclose,noctx,gosec
		if err != nil {
			return nil, fmt.Errorf("failed to download file %s: %w", fileURL, err)
		}

		if rawResp != nil && rawResp.Body != nil {
			defer goutils.CatchWarnErrorFunc(rawResp.Body.Close) //nolint:revive
		}

		if rawResp.StatusCode != http.StatusOK {
			rawBody, err := io.ReadAll(rawResp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to download %s schema: %s", fileURL, rawResp.Status) //nolint
			}

			return nil, fmt.Errorf("failed to download %s schema: %s", fileURL, string(rawBody)) //nolint
		}

		jsonSchema := new(jsonschema.Schema)

		err = json.NewDecoder(rawResp.Body).Decode(jsonSchema)
		if err != nil {
			return nil, fmt.Errorf("failed to decode gohttpc schema: %w", err)
		}

		results = append(results, jsonSchema)
	}

	return results, nil
}
