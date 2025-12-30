package authmode

import (
	"context"
	"testing"

	"github.com/hasura/goenvconf"
	"github.com/relychan/goutils"
	"gotest.tools/v3/assert"
)

func TestRelyAuthHeaderAllowListSetting_IsZero(t *testing.T) {
	t.Run("zero_empty", func(t *testing.T) {
		setting := RelyAuthIPAllowListConfig{}
		assert.Assert(t, setting.IsZero())
	})

	t.Run("non_zero_with_headers", func(t *testing.T) {
		setting := RelyAuthIPAllowListConfig{
			Headers: []string{"x-forwarded-for"},
		}
		assert.Assert(t, !setting.IsZero())
	})

	t.Run("non_zero_with_patterns", func(t *testing.T) {
		setting := RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		assert.Assert(t, !setting.IsZero())
	})
}

func TestRelyAuthHeaderAllowListSetting_Equal(t *testing.T) {
	t.Run("equal_empty", func(t *testing.T) {
		a := RelyAuthIPAllowListConfig{}
		b := RelyAuthIPAllowListConfig{}
		assert.Assert(t, a.Equal(b))
	})

	t.Run("equal_with_values", func(t *testing.T) {
		a := RelyAuthIPAllowListConfig{
			Headers: []string{"x-forwarded-for"},
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		b := RelyAuthIPAllowListConfig{
			Headers: []string{"x-forwarded-for"},
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		assert.Assert(t, a.Equal(b))
	})

	t.Run("not_equal_different_headers", func(t *testing.T) {
		a := RelyAuthIPAllowListConfig{
			Headers: []string{"x-forwarded-for"},
		}
		b := RelyAuthIPAllowListConfig{
			Headers: []string{"x-real-ip"},
		}
		assert.Assert(t, !a.Equal(b))
	})

	t.Run("not_equal_different_patterns", func(t *testing.T) {
		a := RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		b := RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"10.0.0.0/8"})),
			},
		}
		assert.Assert(t, !a.Equal(b))
	})
}

func TestRelyAuthSecurityRulesConfig_IsZero(t *testing.T) {
	t.Run("zero_empty", func(t *testing.T) {
		config := RelyAuthSecurityRulesConfig{}
		assert.Assert(t, config.IsZero())
	})

	t.Run("zero_nil_pointers", func(t *testing.T) {
		config := RelyAuthSecurityRulesConfig{
			AllowedIPs: nil,
		}
		assert.Assert(t, config.IsZero())
	})

	t.Run("zero_empty_settings", func(t *testing.T) {
		config := RelyAuthSecurityRulesConfig{
			AllowedIPs:  &RelyAuthIPAllowListConfig{},
			HeaderRules: map[string]RelyAuthAllowListConfig{},
		}
		assert.Assert(t, config.IsZero())
	})

	t.Run("non_zero_with_allowed_ips", func(t *testing.T) {
		config := RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				RelyAuthAllowListConfig: RelyAuthAllowListConfig{
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
				},
			},
		}
		assert.Assert(t, !config.IsZero())
	})

	t.Run("non_zero_with_allowed_hosts", func(t *testing.T) {
		config := RelyAuthSecurityRulesConfig{
			HeaderRules: map[string]RelyAuthAllowListConfig{
				"Test": {
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"*.example.com"})),
				},
			},
		}
		assert.Assert(t, !config.IsZero())
	})
}

func TestRelyAuthSecurityRulesConfig_Equal(t *testing.T) {
	t.Run("equal_empty", func(t *testing.T) {
		a := RelyAuthSecurityRulesConfig{}
		b := RelyAuthSecurityRulesConfig{}
		assert.Assert(t, a.Equal(b))
	})

	t.Run("equal_with_values", func(t *testing.T) {
		a := RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				RelyAuthAllowListConfig: RelyAuthAllowListConfig{
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
				},
			},
		}
		b := RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				RelyAuthAllowListConfig: RelyAuthAllowListConfig{
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
				},
			},
		}
		assert.Assert(t, a.Equal(b))
	})

	t.Run("not_equal_different_ips", func(t *testing.T) {
		a := RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				RelyAuthAllowListConfig: RelyAuthAllowListConfig{
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
				},
			},
		}
		b := RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				RelyAuthAllowListConfig: RelyAuthAllowListConfig{
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"10.0.0.0/8"})),
				},
			},
		}
		assert.Assert(t, !a.Equal(b))
	})
}

func TestRelyAuthAllowedIPsFromConfig(t *testing.T) {
	t.Run("nil_config", func(t *testing.T) {
		result, err := AllowedIPsFromConfig(nil, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, ErrEmptyAllowedIPs.Error())
		assert.Assert(t, result == nil)
	})

	t.Run("empty_patterns", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, ErrEmptyAllowedIPs.Error())
		assert.Assert(t, result == nil)
	})

	t.Run("valid_single_ip", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.100"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 1, len(result.Include))
		assert.Equal(t, "192.168.1.100/32", result.Include[0].String())
	})

	t.Run("valid_subnet", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 1, len(result.Include))
		assert.Equal(t, "192.168.1.0/24", result.Include[0].String())
	})

	t.Run("multiple_ips_and_subnets", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{
					"192.168.1.0/24",
					"10.0.0.1",
					"172.16.0.0/16",
				})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 3, len(result.Include))
	})

	t.Run("with_custom_headers", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Headers: []string{"X-Real-IP", "X-Forwarded-For"},
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 2, len(result.Headers))
		// Headers are sorted alphabetically
		assert.Equal(t, "x-forwarded-for", result.Headers[0])
		assert.Equal(t, "x-real-ip", result.Headers[1])
	})

	t.Run("invalid_ip", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"invalid-ip"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.Assert(t, err != nil)
		assert.Assert(t, result == nil)
	})

	t.Run("duplicate_ips_removed", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{
					"192.168.1.0/24",
					"192.168.1.0/24",
					"10.0.0.1",
				})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 2, len(result.Include))
	})

	t.Run("empty_strings_ignored", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Headers: []string{"", "X-Real-IP", ""},
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"  ", "192.168.1.0/24", "  "})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 1, len(result.Headers))
		assert.Equal(t, 1, len(result.Include))
	})
}

func TestRelyAuthAllowedIPs_Validate(t *testing.T) {
	t.Run("allowed_ip_in_subnet", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{
					"192.168.1.0/24",
				})),
			},
		}
		allowedIPs, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip": "192.168.1.100",
			},
		}
		err = allowedIPs.Validate(body)
		assert.NilError(t, err)
	})

	t.Run("disallowed_ip", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{
					"192.168.1.0/24",
				})),
			},
		}
		allowedIPs, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip": "10.0.0.1",
			},
		}
		err = allowedIPs.Validate(body)
		assert.ErrorContains(t, err, ErrDisallowedIP.Error())
	})

	t.Run("ip_not_found", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{
					"192.168.1.0/24",
				})),
			},
		}
		allowedIPs, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{},
		}
		err = allowedIPs.Validate(body)
		assert.ErrorContains(t, err, ErrIPNotFound.Error())
	})

	t.Run("custom_header", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Headers: []string{"X-Custom-IP"},
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{
					"192.168.1.0/24",
				})),
			},
		}
		allowedIPs, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-custom-ip": "192.168.1.50",
			},
		}
		err = allowedIPs.Validate(body)
		assert.NilError(t, err)
	})
}

func TestParseSubnet(t *testing.T) {
	t.Run("valid_cidr", func(t *testing.T) {
		subnet, err := ParseSubnet("192.168.1.0/24")
		assert.NilError(t, err)
		assert.Assert(t, subnet != nil)
		assert.Equal(t, "192.168.1.0/24", subnet.String())
	})

	t.Run("single_ip_auto_cidr", func(t *testing.T) {
		subnet, err := ParseSubnet("192.168.1.100")
		assert.NilError(t, err)
		assert.Assert(t, subnet != nil)
		assert.Equal(t, "192.168.1.100/32", subnet.String())
	})

	t.Run("empty_string", func(t *testing.T) {
		subnet, err := ParseSubnet("")
		assert.ErrorContains(t, err, ErrInvalidSubnet.Error())
		assert.Assert(t, subnet == nil)
	})

	t.Run("invalid_ip", func(t *testing.T) {
		subnet, err := ParseSubnet("invalid-ip")
		assert.Assert(t, err != nil)
		assert.Assert(t, subnet == nil)
	})
}

func TestGetClientIP(t *testing.T) {
	t.Run("from_x_real_ip", func(t *testing.T) {
		headers := map[string]string{
			"x-real-ip": "192.168.1.100",
		}
		ip, err := GetClientIP(headers)
		assert.NilError(t, err)
		assert.Equal(t, "192.168.1.100", ip.String())
	})

	t.Run("from_x_forwarded_for", func(t *testing.T) {
		headers := map[string]string{
			"x-forwarded-for": "10.0.0.1",
		}
		ip, err := GetClientIP(headers)
		assert.NilError(t, err)
		assert.Equal(t, "10.0.0.1", ip.String())
	})

	t.Run("from_cf_connecting_ip", func(t *testing.T) {
		headers := map[string]string{
			"cf-connecting-ip": "172.16.0.1",
		}
		ip, err := GetClientIP(headers)
		assert.NilError(t, err)
		assert.Equal(t, "172.16.0.1", ip.String())
	})

	t.Run("custom_header", func(t *testing.T) {
		headers := map[string]string{
			"x-custom-ip": "192.168.1.50",
		}
		ip, err := GetClientIP(headers, "x-custom-ip")
		assert.NilError(t, err)
		assert.Equal(t, "192.168.1.50", ip.String())
	})

	t.Run("empty_headers", func(t *testing.T) {
		headers := map[string]string{}
		ip, err := GetClientIP(headers)
		assert.ErrorContains(t, err, ErrIPNotFound.Error())
		assert.Assert(t, ip == nil)
	})

	t.Run("invalid_ip", func(t *testing.T) {
		headers := map[string]string{
			"x-real-ip": "invalid-ip",
		}
		ip, err := GetClientIP(headers)
		assert.ErrorContains(t, err, ErrInvalidIP.Error())
		assert.Assert(t, ip == nil)
	})
}

func TestRelyAuthentication_Authenticate(t *testing.T) {
	t.Run("no_security_rules", func(t *testing.T) {
		// Create a mock authenticator
		mockAuth := &mockAuthenticator{
			mode: AuthModeAPIKey,
			output: AuthenticatedOutput{
				ID:               "test-id",
				Mode:             AuthModeAPIKey,
				SessionVariables: map[string]any{"x-hasura-role": "user"},
			},
		}

		auth := &RelyAuthentication{
			RelyAuthenticator: mockAuth,
			SecurityRules:     nil,
		}

		body := &AuthenticateRequestData{
			Headers: map[string]string{},
		}

		result, err := auth.Authenticate(context.Background(), body)
		assert.NilError(t, err)
		assert.Equal(t, "test-id", result.ID)
		assert.Equal(t, AuthModeAPIKey, result.Mode)
	})

	t.Run("with_security_rules_pass", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				RelyAuthAllowListConfig: RelyAuthAllowListConfig{
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{
						"192.168.1.0/24",
					})),
				},
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		mockAuth := &mockAuthenticator{
			mode: AuthModeAPIKey,
			output: AuthenticatedOutput{
				ID:               "test-id",
				Mode:             AuthModeAPIKey,
				SessionVariables: map[string]any{"x-hasura-role": "user"},
			},
		}

		auth := &RelyAuthentication{
			RelyAuthenticator: mockAuth,
			SecurityRules:     rules,
		}

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip": "192.168.1.100",
			},
		}

		result, err := auth.Authenticate(context.Background(), body)
		assert.NilError(t, err)
		assert.Equal(t, "test-id", result.ID)
	})

	t.Run("with_security_rules_fail", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				RelyAuthAllowListConfig: RelyAuthAllowListConfig{
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{
						"192.168.1.0/24",
					})),
				},
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		mockAuth := &mockAuthenticator{
			mode: AuthModeAPIKey,
		}

		auth := &RelyAuthentication{
			RelyAuthenticator: mockAuth,
			SecurityRules:     rules,
		}

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip": "10.0.0.1",
			},
		}

		result, err := auth.Authenticate(context.Background(), body)
		assert.ErrorContains(t, err, ErrDisallowedIP.Error())
		assert.Equal(t, AuthModeAPIKey, result.Mode)
	})
}

// mockAuthenticator is a mock implementation of RelyAuthenticator for testing
type mockAuthenticator struct {
	mode   AuthMode
	output AuthenticatedOutput
	err    error
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, body *AuthenticateRequestData) (AuthenticatedOutput, error) {
	if m.err != nil {
		return AuthenticatedOutput{}, m.err
	}
	return m.output, nil
}

// IDs returns identities of this authenticator.
func (m *mockAuthenticator) IDs() []string {
	return []string{}
}

func (m *mockAuthenticator) Mode() AuthMode {
	return m.mode
}

func (m *mockAuthenticator) Close() error {
	return nil
}

// Tests for RelyAuthAllowListMatcherRule

func TestAllowListMatcherRuleFromConfig(t *testing.T) {
	t.Run("nil_config", func(t *testing.T) {
		config := RelyAuthAllowListConfig{}
		result, err := AllowListMatcherRuleFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 0, len(result.Include))
		assert.Equal(t, 0, len(result.Exclude))
	})

	t.Run("with_include_patterns", func(t *testing.T) {
		config := RelyAuthAllowListConfig{
			Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*", "^Token .*"})),
		}
		result, err := AllowListMatcherRuleFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 2, len(result.Include))
		assert.Equal(t, 0, len(result.Exclude))
	})

	t.Run("with_exclude_patterns", func(t *testing.T) {
		config := RelyAuthAllowListConfig{
			Exclude: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Blocked.*"})),
		}
		result, err := AllowListMatcherRuleFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 0, len(result.Include))
		assert.Equal(t, 1, len(result.Exclude))
	})

	t.Run("with_both_include_and_exclude", func(t *testing.T) {
		config := RelyAuthAllowListConfig{
			Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
			Exclude: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer test.*"})),
		}
		result, err := AllowListMatcherRuleFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 1, len(result.Include))
		assert.Equal(t, 1, len(result.Exclude))
	})

	t.Run("invalid_include_regex", func(t *testing.T) {
		config := RelyAuthAllowListConfig{
			Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"[invalid"})),
		}
		result, err := AllowListMatcherRuleFromConfig(config, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, "include")
		assert.Assert(t, result == nil)
	})

	t.Run("invalid_exclude_regex", func(t *testing.T) {
		config := RelyAuthAllowListConfig{
			Exclude: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"[invalid"})),
		}
		result, err := AllowListMatcherRuleFromConfig(config, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, "exclude")
		assert.Assert(t, result == nil)
	})

	t.Run("empty_string_in_patterns", func(t *testing.T) {
		config := RelyAuthAllowListConfig{
			Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{""})),
		}
		result, err := AllowListMatcherRuleFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 0, len(result.Include))
	})
}

func TestRelyAuthAllowListMatcherRule_IsValid(t *testing.T) {
	t.Run("no_rules_always_valid", func(t *testing.T) {
		rule := RelyAuthAllowListMatcherRule{}
		assert.Assert(t, rule.IsValid("any value"))
	})

	t.Run("include_rule_matches", func(t *testing.T) {
		config := RelyAuthAllowListConfig{
			Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
		}
		matcherRule, err := AllowListMatcherRuleFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		assert.Assert(t, matcherRule.IsValid("Bearer token123"))
		assert.Assert(t, !matcherRule.IsValid("Token abc"))
	})

	t.Run("multiple_include_rules_all_must_match", func(t *testing.T) {
		config := RelyAuthAllowListConfig{
			Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*", ".*token.*"})),
		}
		matcherRule, err := AllowListMatcherRuleFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		assert.Assert(t, matcherRule.IsValid("Bearer token123"))
		assert.Assert(t, !matcherRule.IsValid("Bearer abc"))
		assert.Assert(t, !matcherRule.IsValid("Token token123"))
	})

	t.Run("exclude_rule_blocks", func(t *testing.T) {
		config := RelyAuthAllowListConfig{
			Exclude: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Blocked.*"})),
		}
		matcherRule, err := AllowListMatcherRuleFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		assert.Assert(t, matcherRule.IsValid("Allowed value"))
		assert.Assert(t, !matcherRule.IsValid("Blocked value"))
	})

	t.Run("include_and_exclude_rules", func(t *testing.T) {
		config := RelyAuthAllowListConfig{
			Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
			Exclude: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{".*test.*"})),
		}
		matcherRule, err := AllowListMatcherRuleFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		assert.Assert(t, matcherRule.IsValid("Bearer production"))
		assert.Assert(t, !matcherRule.IsValid("Bearer test"))
		assert.Assert(t, !matcherRule.IsValid("Token production"))
	})
}

// Tests for HeaderRulesFromConfig

func TestHeaderRulesFromConfig(t *testing.T) {
	t.Run("nil_config", func(t *testing.T) {
		result, err := HeaderRulesFromConfig(nil, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 0, len(result))
	})

	t.Run("empty_config", func(t *testing.T) {
		config := map[string]RelyAuthAllowListConfig{}
		result, err := HeaderRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 0, len(result))
	})

	t.Run("single_header_rule", func(t *testing.T) {
		config := map[string]RelyAuthAllowListConfig{
			"Authorization": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
			},
		}
		result, err := HeaderRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 1, len(result))
		_, ok := result["authorization"]
		assert.Assert(t, ok)
	})

	t.Run("multiple_header_rules", func(t *testing.T) {
		config := map[string]RelyAuthAllowListConfig{
			"Authorization": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
			},
			"X-API-Key": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^[a-zA-Z0-9]{32}$"})),
			},
		}
		result, err := HeaderRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 2, len(result))
		_, ok := result["authorization"]
		assert.Assert(t, ok)
		_, ok = result["x-api-key"]
		assert.Assert(t, ok)
	})

	t.Run("case_insensitive_header_names", func(t *testing.T) {
		config := map[string]RelyAuthAllowListConfig{
			"AUTHORIZATION": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
			},
		}
		result, err := HeaderRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		_, ok := result["authorization"]
		assert.Assert(t, ok)
	})

	t.Run("invalid_regex_in_rule", func(t *testing.T) {
		config := map[string]RelyAuthAllowListConfig{
			"Authorization": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"[invalid"})),
			},
		}
		result, err := HeaderRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, "failed to parse header rule")
		assert.ErrorContains(t, err, "Authorization")
		assert.Assert(t, result == nil)
	})
}

// Tests for RelyAuthHeaderRules.Validate

func TestRelyAuthHeaderRules_Validate(t *testing.T) {
	t.Run("empty_rules", func(t *testing.T) {
		rules := RelyAuthHeaderRules{}
		body := &AuthenticateRequestData{
			Headers: map[string]string{},
		}
		err := rules.Validate(body)
		assert.NilError(t, err)
	})

	t.Run("rules_exist_but_no_headers", func(t *testing.T) {
		config := map[string]RelyAuthAllowListConfig{
			"Authorization": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
			},
		}
		rules, err := HeaderRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{},
		}
		err = rules.Validate(body)
		assert.ErrorContains(t, err, ErrInvalidHeader.Error())
		assert.ErrorContains(t, err, "headers are required")
	})

	t.Run("header_missing", func(t *testing.T) {
		config := map[string]RelyAuthAllowListConfig{
			"Authorization": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
			},
		}
		rules, err := HeaderRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-api-key": "test",
			},
		}
		err = rules.Validate(body)
		assert.ErrorContains(t, err, ErrInvalidHeader.Error())
		assert.ErrorContains(t, err, "does not exist")
	})

	t.Run("header_value_matches", func(t *testing.T) {
		config := map[string]RelyAuthAllowListConfig{
			"Authorization": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
			},
		}
		rules, err := HeaderRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"authorization": "Bearer token123",
			},
		}
		err = rules.Validate(body)
		assert.NilError(t, err)
	})

	t.Run("header_value_does_not_match", func(t *testing.T) {
		config := map[string]RelyAuthAllowListConfig{
			"Authorization": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
			},
		}
		rules, err := HeaderRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"authorization": "Token abc",
			},
		}
		err = rules.Validate(body)
		assert.ErrorContains(t, err, ErrInvalidHeader.Error())
		assert.ErrorContains(t, err, "does not satisfy security rules")
	})

	t.Run("multiple_headers_all_match", func(t *testing.T) {
		config := map[string]RelyAuthAllowListConfig{
			"Authorization": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
			},
			"X-API-Key": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^[a-zA-Z0-9]{32}$"})),
			},
		}
		rules, err := HeaderRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"authorization": "Bearer token123",
				"x-api-key":     "abcdefghijklmnopqrstuvwxyz123456",
			},
		}
		err = rules.Validate(body)
		assert.NilError(t, err)
	})

	t.Run("multiple_headers_one_fails", func(t *testing.T) {
		config := map[string]RelyAuthAllowListConfig{
			"Authorization": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
			},
			"X-API-Key": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^[a-zA-Z0-9]{32}$"})),
			},
		}
		rules, err := HeaderRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"authorization": "Bearer token123",
				"x-api-key":     "short",
			},
		}
		err = rules.Validate(body)
		assert.ErrorContains(t, err, ErrInvalidHeader.Error())
	})

	t.Run("exclude_pattern_blocks", func(t *testing.T) {
		config := map[string]RelyAuthAllowListConfig{
			"Authorization": {
				Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
				Exclude: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{".*test.*"})),
			},
		}
		rules, err := HeaderRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"authorization": "Bearer test-token",
			},
		}
		err = rules.Validate(body)
		assert.ErrorContains(t, err, ErrInvalidHeader.Error())
	})
}

// Additional tests for RelyAuthSecurityRulesFromConfig with HeaderRules

func TestRelyAuthSecurityRulesFromConfig_WithHeaderRules(t *testing.T) {
	t.Run("with_header_rules_only", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			HeaderRules: map[string]RelyAuthAllowListConfig{
				"Authorization": {
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
				},
			},
		}
		result, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.AllowedIPs == nil)
		assert.Equal(t, 1, len(result.HeaderRules))
	})

	t.Run("with_both_allowed_ips_and_header_rules", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				RelyAuthAllowListConfig: RelyAuthAllowListConfig{
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
				},
			},
			HeaderRules: map[string]RelyAuthAllowListConfig{
				"Authorization": {
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
				},
			},
		}
		result, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.AllowedIPs != nil)
		assert.Equal(t, 1, len(result.HeaderRules))
	})

	t.Run("invalid_header_rule_regex", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			HeaderRules: map[string]RelyAuthAllowListConfig{
				"Authorization": {
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"[invalid"})),
				},
			},
		}
		result, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, "failed to parse header rule")
		assert.Assert(t, result != nil) // result is still returned even on error
	})

	t.Run("empty_header_rules_map", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			HeaderRules: map[string]RelyAuthAllowListConfig{},
		}
		result, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 0, len(result.HeaderRules))
	})
}

// Additional tests for RelyAuthSecurityRules.Validate with HeaderRules

func TestRelyAuthSecurityRules_Validate_WithHeaderRules(t *testing.T) {
	t.Run("header_rules_only_pass", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			HeaderRules: map[string]RelyAuthAllowListConfig{
				"Authorization": {
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
				},
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"authorization": "Bearer token123",
			},
		}
		err = rules.Validate(body)
		assert.NilError(t, err)
	})

	t.Run("header_rules_only_fail", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			HeaderRules: map[string]RelyAuthAllowListConfig{
				"Authorization": {
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
				},
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"authorization": "Token abc",
			},
		}
		err = rules.Validate(body)
		assert.ErrorContains(t, err, ErrInvalidHeader.Error())
	})

	t.Run("both_ip_and_header_rules_pass", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				RelyAuthAllowListConfig: RelyAuthAllowListConfig{
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
				},
			},
			HeaderRules: map[string]RelyAuthAllowListConfig{
				"Authorization": {
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
				},
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip":     "192.168.1.100",
				"authorization": "Bearer token123",
			},
		}
		err = rules.Validate(body)
		assert.NilError(t, err)
	})

	t.Run("both_ip_and_header_rules_ip_fails", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				RelyAuthAllowListConfig: RelyAuthAllowListConfig{
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
				},
			},
			HeaderRules: map[string]RelyAuthAllowListConfig{
				"Authorization": {
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
				},
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip":     "10.0.0.1",
				"authorization": "Bearer token123",
			},
		}
		err = rules.Validate(body)
		assert.ErrorContains(t, err, ErrDisallowedIP.Error())
	})

	t.Run("both_ip_and_header_rules_header_fails", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				RelyAuthAllowListConfig: RelyAuthAllowListConfig{
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
				},
			},
			HeaderRules: map[string]RelyAuthAllowListConfig{
				"Authorization": {
					Include: goutils.ToPtr(goenvconf.NewEnvStringSliceValue([]string{"^Bearer .*"})),
				},
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip":     "192.168.1.100",
				"authorization": "Token abc",
			},
		}
		err = rules.Validate(body)
		assert.ErrorContains(t, err, ErrInvalidHeader.Error())
	})

	t.Run("nil_header_rules", func(t *testing.T) {
		rules := &RelyAuthSecurityRules{
			HeaderRules: nil,
		}
		body := &AuthenticateRequestData{
			Headers: map[string]string{},
		}
		err := rules.Validate(body)
		assert.NilError(t, err)
	})
}
