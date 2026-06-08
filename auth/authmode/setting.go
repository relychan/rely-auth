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

package authmode

import (
	"github.com/hasura/goenvconf"
	"github.com/invopop/jsonschema"
	"github.com/relychan/goutils"
)

// RelyAuthSettings holds global settings for the authenticators.
type RelyAuthSettings struct {
	// The interval in seconds to reload JSON web keys from the remote URL.
	// If the value is zero or negative, disables the process.
	ReloadInterval int `json:"reloadInterval,omitempty" yaml:"reloadInterval,omitempty" jsonschema:"minimum=0,default=0"`
}

// RelyAuthAllowListConfig represents a common setting for allow list.
type RelyAuthAllowListConfig struct {
	// List of allowed patterns.
	Include *goenvconf.EnvStringSlice `json:"include,omitempty" yaml:"include,omitempty"`
	// List of disallowed patterns.
	Exclude *goenvconf.EnvStringSlice `json:"exclude,omitempty" yaml:"exclude,omitempty"`
}

// IsZero if the current instance is empty.
func (hal RelyAuthAllowListConfig) IsZero() bool {
	return (hal.Include == nil || hal.Include.IsZero()) &&
		(hal.Exclude == nil || hal.Exclude.IsZero())
}

// Equal checks if the target value is equal.
func (hal RelyAuthAllowListConfig) Equal(target RelyAuthAllowListConfig) bool {
	return goutils.EqualPtr(hal.Include, target.Include) &&
		goutils.EqualPtr(hal.Exclude, target.Exclude)
}

// RelyAuthIPAllowListConfig represents a setting for IP allow list.
// Note that IP headers aren't safe and can be spoofed by the client. Therefore, make sure that the header of origin IPs is trusted.
// Read more details at https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For#security_and_privacy_concerns
type RelyAuthIPAllowListConfig struct {
	RelyAuthAllowListConfig `yaml:",inline"`

	// The location of the IP to select. Default is the X-Forwarded-For header.
	Location ClientIPLocation `json:"location,omitempty" yaml:"location,omitempty"`
	// Allow public IPs only.
	PublicOnly bool `json:"publicOnly,omitempty" yaml:"publicOnly,omitempty"`
	// The exact number of trusted reverse proxies between this server and the public internet. Required if location=x_forwarded_for.
	NumTrustedProxies int32 `json:"numTrustedProxies,omitempty" yaml:"numTrustedProxies,omitempty"`
	// Proxy IPs must be in these trusted proxy prefixes. Ignore if empty. This configuration is available if location=x_forwarded_for.
	TrustedProxyIPPrefixes []string `json:"trustedProxyIpPrefixes,omitempty" yaml:"trustedProxyIpPrefixes,omitempty"`
	// The client IP could be in this header list. Required if location=header.
	Headers []string `json:"headers,omitempty" yaml:"headers,omitempty"`
}

// IsZero if the current instance is empty.
func (hal RelyAuthIPAllowListConfig) IsZero() bool {
	return len(hal.Headers) == 0 && hal.RelyAuthAllowListConfig.IsZero() &&
		hal.Location == 0 && !hal.PublicOnly && hal.NumTrustedProxies == 0 &&
		len(hal.TrustedProxyIPPrefixes) == 0
}

// Equal checks if the target value is equal.
func (hal RelyAuthIPAllowListConfig) Equal(target RelyAuthIPAllowListConfig) bool {
	return goutils.EqualSliceSorted(hal.Headers, target.Headers) &&
		hal.RelyAuthAllowListConfig.Equal(target.RelyAuthAllowListConfig) &&
		hal.Location == target.Location &&
		hal.PublicOnly == target.PublicOnly &&
		hal.NumTrustedProxies == target.NumTrustedProxies &&
		goutils.EqualSliceSorted(hal.TrustedProxyIPPrefixes, target.TrustedProxyIPPrefixes)
}

// JSONSchemaExtend extends the JSON schema with custom fields.
func (RelyAuthIPAllowListConfig) JSONSchemaExtend(schema *jsonschema.Schema) {
	schema.Properties.Delete("location")

	numTrustedProxies, _ := schema.Properties.Delete("numTrustedProxies")

	trustedProxyIPPrefixes, _ := schema.Properties.Delete("trustedProxyIpPrefixes")
	trustedProxyIPPrefixes.Items.Pattern = `^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\/([0-9]+))|((([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\\/([0-9]+)))$` //nolint:lll

	headers, _ := schema.Properties.Delete("headers")
	headers.MinItems = new(uint64(1))
	headers.Items.Pattern = `^[A-Za-z0-9!#\$%&'*+\-.^_|~]+$`

	xffProps := jsonschema.NewProperties()
	xffProps.Set("location", &jsonschema.Schema{
		Type:        "string",
		Enum:        []any{"x_forwarded_for"},
		Description: "The location of the IP to select.",
	})
	xffProps.Set("numTrustedProxies", numTrustedProxies)
	xffProps.Set("trustedProxyIpPrefixes", trustedProxyIPPrefixes)

	remoteAddrProps := jsonschema.NewProperties()
	remoteAddrProps.Set("location", &jsonschema.Schema{
		Type:        "string",
		Enum:        []any{"remote_addr"},
		Description: "The location of the IP to select.",
	})

	headersProps := jsonschema.NewProperties()
	headersProps.Set("location", &jsonschema.Schema{
		Type:        "string",
		Enum:        []any{"header"},
		Description: "The location of the IP to select.",
	})
	headersProps.Set("headers", headers)

	schema.OneOf = []*jsonschema.Schema{
		{
			Title:      "ClientIPFromXForwardedFor",
			Type:       "object",
			Required:   []string{"location"},
			Properties: xffProps,
		}, {
			Title:      "ClientIPFromHeader",
			Type:       "object",
			Required:   []string{"location", "headers"},
			Properties: headersProps,
		}, {
			Title:      "ClientIPFromRemoteAddr",
			Type:       "object",
			Required:   []string{"location"},
			Properties: remoteAddrProps,
		},
	}
}

// RelyAuthSecurityRulesConfig defines configurations of security rules.
type RelyAuthSecurityRulesConfig struct {
	// Configure the list of allowed IPs.
	AllowedIPs *RelyAuthIPAllowListConfig `json:"allowedIPs,omitempty" yaml:"allowedIPs,omitempty"`
	// Configure the map of header rules.
	HeaderRules map[string]RelyAuthAllowListConfig `json:"headerRules,omitempty" yaml:"headerRules,omitempty"`
}

// IsZero if the current instance is empty.
func (es RelyAuthSecurityRulesConfig) IsZero() bool {
	return (es.AllowedIPs == nil || es.AllowedIPs.IsZero()) &&
		len(es.HeaderRules) == 0
}

// Equal checks if the target value is equal.
func (es RelyAuthSecurityRulesConfig) Equal(target RelyAuthSecurityRulesConfig) bool {
	return goutils.EqualPtr(es.AllowedIPs, target.AllowedIPs) &&
		goutils.EqualMap(es.HeaderRules, target.HeaderRules, true)
}
