package authmode

import (
	"slices"

	"github.com/hasura/goenvconf"
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

	// The position of the IP to select if the X-Forwarded-For header has many IPs. Default is rightmost.
	Position ForwardedIPPosition `json:"position,omitempty" yaml:"position,omitempty"`
	// Allow public IPs only.
	PublicOnly bool `json:"publicOnly,omitempty" yaml:"publicOnly,omitempty"`
	// The client IP could be in this header list. Use default client IP headers if empty.
	Headers []string `json:"headers,omitempty" yaml:"headers,omitempty"`
}

// IsZero if the current instance is empty.
func (hal RelyAuthIPAllowListConfig) IsZero() bool {
	return len(hal.Headers) == 0 && hal.RelyAuthAllowListConfig.IsZero() &&
		hal.Position == "" && !hal.PublicOnly
}

// Equal checks if the target value is equal.
func (hal RelyAuthIPAllowListConfig) Equal(target RelyAuthIPAllowListConfig) bool {
	return slices.Equal(hal.Headers, target.Headers) &&
		hal.RelyAuthAllowListConfig.Equal(target.RelyAuthAllowListConfig) &&
		hal.Position == target.Position &&
		hal.PublicOnly == target.PublicOnly
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
