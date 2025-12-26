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

// RelyAuthIPAllowListConfig represents a setting for IP allow list.
type RelyAuthIPAllowListConfig struct {
	Headers  []string                 `json:"headers,omitempty" yaml:"headers,omitempty"`
	Patterns goenvconf.EnvStringSlice `json:"patterns" yaml:"patterns"`
}

// IsZero if the current instance is empty.
func (hal RelyAuthIPAllowListConfig) IsZero() bool {
	return len(hal.Headers) == 0 && hal.Patterns.IsZero()
}

// Equal checks if the target value is equal.
func (hal RelyAuthIPAllowListConfig) Equal(target RelyAuthIPAllowListConfig) bool {
	return slices.Equal(hal.Headers, target.Headers) &&
		hal.Patterns.Equal(target.Patterns)
}

// RelyAuthSecurityRulesConfig defines configurations of security rules.
type RelyAuthSecurityRulesConfig struct {
	// Configure the list of allowed IPs.
	AllowedIPs *RelyAuthIPAllowListConfig `json:"allowedIPs,omitempty" yaml:"allowedIPs,omitempty"`
	// Configure the map of header rules.
	HeaderRules map[string]goenvconf.EnvStringSlice `json:"headerRules,omitempty" yaml:"headerRules,omitempty"`
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

// RelyAuthSecurityRules defines rules to harden the security.
type RelyAuthSecurityRules struct {
	// Configure the list of allowed IPs.
	AllowedIPs *RelyAuthAllowedIPs
	// Configure the list of extra header rules.
	HeaderRules RelyAuthHeaderRules
}

// RelyAuthSecurityRulesFromConfig creates a [RelyAuthSecurityRules] from configurations.
func RelyAuthSecurityRulesFromConfig(
	conf *RelyAuthSecurityRulesConfig,
	getEnvFunc goenvconf.GetEnvFunc,
) (*RelyAuthSecurityRules, error) {
	result := &RelyAuthSecurityRules{
		HeaderRules: make(RelyAuthHeaderRules),
	}

	if conf == nil {
		return result, nil
	}

	if conf.AllowedIPs != nil {
		allowedIPs, err := RelyAuthAllowedIPsFromConfig(conf.AllowedIPs, getEnvFunc)
		if err != nil {
			return result, err
		}

		result.AllowedIPs = allowedIPs
	}

	if len(conf.HeaderRules) > 0 {
		headerRules, err := RelyAuthHeaderRulesFromConfig(conf.HeaderRules, getEnvFunc)
		if err != nil {
			return result, err
		}

		result.HeaderRules = headerRules
	}

	return result, nil
}

// Validate checks if the webhook request satisfies security rules.
func (sr *RelyAuthSecurityRules) Validate(body *AuthenticateRequestData) error {
	if sr.AllowedIPs != nil {
		err := sr.AllowedIPs.Validate(body)
		if err != nil {
			return err
		}
	}

	if sr.HeaderRules != nil {
		err := sr.HeaderRules.Validate(body)
		if err != nil {
			return err
		}
	}

	return nil
}
