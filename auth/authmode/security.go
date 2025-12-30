package authmode

import "github.com/hasura/goenvconf"

// RelyAuthSecurityRules defines rules to harden the security.
type RelyAuthSecurityRules struct {
	// Configure the list of allowed IPs.
	AllowedIPs *RelyAuthIPAllowList
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
		allowedIPs, err := AllowedIPsFromConfig(conf.AllowedIPs, getEnvFunc)
		if err != nil {
			return result, err
		}

		result.AllowedIPs = allowedIPs
	}

	if len(conf.HeaderRules) > 0 {
		headerRules, err := HeaderRulesFromConfig(conf.HeaderRules, getEnvFunc)
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
