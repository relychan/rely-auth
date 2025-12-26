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

// RelyAuthHeaderAllowListSetting represents a setting for header allow list.
type RelyAuthHeaderAllowListSetting struct {
	Headers  []string                 `json:"headers,omitempty" yaml:"headers,omitempty"`
	Patterns goenvconf.EnvStringSlice `json:"patterns" yaml:"patterns"`
}

// IsZero if the current instance is empty.
func (hal RelyAuthHeaderAllowListSetting) IsZero() bool {
	return len(hal.Headers) == 0 && hal.Patterns.IsZero()
}

// Equal checks if the target value is equal.
func (hal RelyAuthHeaderAllowListSetting) Equal(target RelyAuthHeaderAllowListSetting) bool {
	return slices.Equal(hal.Headers, target.Headers) &&
		hal.Patterns.Equal(target.Patterns)
}

// RelyAuthSecurityRulesConfig defines configurations of security rules.
type RelyAuthSecurityRulesConfig struct {
	// Configure the list of allowed IPs.
	AllowedIPs *RelyAuthHeaderAllowListSetting `json:"allowedIPs,omitempty" yaml:"allowedIPs,omitempty"`
	// Configure the list of allowed hosts.
	AllowedHosts *RelyAuthHeaderAllowListSetting `json:"allowedHosts,omitempty" yaml:"allowedHosts,omitempty"`
}

// IsZero if the current instance is empty.
func (es RelyAuthSecurityRulesConfig) IsZero() bool {
	return (es.AllowedIPs == nil || es.AllowedIPs.IsZero()) &&
		(es.AllowedHosts == nil || es.AllowedHosts.IsZero())
}

// Equal checks if the target value is equal.
func (es RelyAuthSecurityRulesConfig) Equal(target RelyAuthSecurityRulesConfig) bool {
	return goutils.EqualPtr(es.AllowedIPs, target.AllowedIPs) &&
		goutils.EqualPtr(es.AllowedHosts, target.AllowedHosts)
}

// RelyAuthSecurityRules defines rules to harden the security.
type RelyAuthSecurityRules struct {
	// Configure the list of allowed IPs.
	AllowedIPs *RelyAuthAllowedIPs
	// Configure the list of allowed hosts.
	AllowedHosts *RelyAuthAllowedHosts
}

// RelyAuthSecurityRulesFromConfig creates a [RelyAuthSecurityRules] from configurations.
func RelyAuthSecurityRulesFromConfig(
	conf *RelyAuthSecurityRulesConfig,
	getEnvFunc goenvconf.GetEnvFunc,
) (*RelyAuthSecurityRules, error) {
	result := &RelyAuthSecurityRules{}

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

	if conf.AllowedHosts != nil {
		allowedHosts, err := RelyAuthAllowedHostsFromConfig(conf.AllowedHosts, getEnvFunc)
		if err != nil {
			return result, err
		}

		result.AllowedHosts = allowedHosts
	}

	return result, nil
}

// Validate checks if the webhook request satisfies security rules.
func (sr *RelyAuthSecurityRules) Validate(body *AuthenticateRequestData) error {
	if sr.AllowedHosts != nil {
		err := sr.AllowedHosts.Validate(body)
		if err != nil {
			return err
		}
	}

	if sr.AllowedIPs != nil {
		err := sr.AllowedIPs.Validate(body)
		if err != nil {
			return err
		}
	}

	return nil
}
