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
)

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
func (sr *RelyAuthSecurityRules) Validate(
	body *AuthenticateRequestData,
) error {
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
