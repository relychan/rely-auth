// Package main generates JSON schemas for the rely-auth config.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/invopop/jsonschema"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth"
	"github.com/relychan/rely-auth/auth/apikey"
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

	reflectSchema.Definitions["AllOrListString"] = &jsonschema.Schema{
		OneOf: []*jsonschema.Schema{
			{
				Type: "string",
				Enum: []any{"*"},
			},
			{
				Type: "array",
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
