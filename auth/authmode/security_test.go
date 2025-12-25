package authmode

import (
	"context"
	"testing"

	"github.com/hasura/goenvconf"
	"gotest.tools/v3/assert"
)

func TestRelyAuthHeaderAllowListSetting_IsZero(t *testing.T) {
	t.Run("zero_empty", func(t *testing.T) {
		setting := RelyAuthHeaderAllowListSetting{}
		assert.Assert(t, setting.IsZero())
	})

	t.Run("non_zero_with_headers", func(t *testing.T) {
		setting := RelyAuthHeaderAllowListSetting{
			Headers: []string{"x-forwarded-for"},
		}
		assert.Assert(t, !setting.IsZero())
	})

	t.Run("non_zero_with_patterns", func(t *testing.T) {
		setting := RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
		}
		assert.Assert(t, !setting.IsZero())
	})
}

func TestRelyAuthHeaderAllowListSetting_Equal(t *testing.T) {
	t.Run("equal_empty", func(t *testing.T) {
		a := RelyAuthHeaderAllowListSetting{}
		b := RelyAuthHeaderAllowListSetting{}
		assert.Assert(t, a.Equal(b))
	})

	t.Run("equal_with_values", func(t *testing.T) {
		a := RelyAuthHeaderAllowListSetting{
			Headers:  []string{"x-forwarded-for"},
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
		}
		b := RelyAuthHeaderAllowListSetting{
			Headers:  []string{"x-forwarded-for"},
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
		}
		assert.Assert(t, a.Equal(b))
	})

	t.Run("not_equal_different_headers", func(t *testing.T) {
		a := RelyAuthHeaderAllowListSetting{
			Headers: []string{"x-forwarded-for"},
		}
		b := RelyAuthHeaderAllowListSetting{
			Headers: []string{"x-real-ip"},
		}
		assert.Assert(t, !a.Equal(b))
	})

	t.Run("not_equal_different_patterns", func(t *testing.T) {
		a := RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
		}
		b := RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"10.0.0.0/8"}),
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
			AllowedIPs:   nil,
			AllowedHosts: nil,
		}
		assert.Assert(t, config.IsZero())
	})

	t.Run("zero_empty_settings", func(t *testing.T) {
		config := RelyAuthSecurityRulesConfig{
			AllowedIPs:   &RelyAuthHeaderAllowListSetting{},
			AllowedHosts: &RelyAuthHeaderAllowListSetting{},
		}
		assert.Assert(t, config.IsZero())
	})

	t.Run("non_zero_with_allowed_ips", func(t *testing.T) {
		config := RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
		}
		assert.Assert(t, !config.IsZero())
	})

	t.Run("non_zero_with_allowed_hosts", func(t *testing.T) {
		config := RelyAuthSecurityRulesConfig{
			AllowedHosts: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"*.example.com"}),
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
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
		}
		b := RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
		}
		assert.Assert(t, a.Equal(b))
	})

	t.Run("not_equal_different_ips", func(t *testing.T) {
		a := RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
		}
		b := RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"10.0.0.0/8"}),
			},
		}
		assert.Assert(t, !a.Equal(b))
	})
}

func TestRelyAuthAllowedIPsFromConfig(t *testing.T) {
	t.Run("nil_config", func(t *testing.T) {
		result, err := RelyAuthAllowedIPsFromConfig(nil, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, ErrEmptyAllowedIPs.Error())
		assert.Assert(t, result == nil)
	})

	t.Run("empty_patterns", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{}
		result, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, ErrEmptyAllowedIPs.Error())
		assert.Assert(t, result == nil)
	})

	t.Run("valid_single_ip", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.100"}),
		}
		result, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 1, len(result.AllowedIPs))
		assert.Equal(t, "192.168.1.100/32", result.AllowedIPs[0].String())
	})

	t.Run("valid_subnet", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
		}
		result, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 1, len(result.AllowedIPs))
		assert.Equal(t, "192.168.1.0/24", result.AllowedIPs[0].String())
	})

	t.Run("multiple_ips_and_subnets", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{
				"192.168.1.0/24",
				"10.0.0.1",
				"172.16.0.0/16",
			}),
		}
		result, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 3, len(result.AllowedIPs))
	})

	t.Run("with_custom_headers", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Headers:  []string{"X-Real-IP", "X-Forwarded-For"},
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
		}
		result, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 2, len(result.Headers))
		// Headers are sorted alphabetically
		assert.Equal(t, "x-forwarded-for", result.Headers[0])
		assert.Equal(t, "x-real-ip", result.Headers[1])
	})

	t.Run("invalid_ip", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"invalid-ip"}),
		}
		result, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.Assert(t, err != nil)
		assert.Assert(t, result == nil)
	})

	t.Run("duplicate_ips_removed", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{
				"192.168.1.0/24",
				"192.168.1.0/24",
				"10.0.0.1",
			}),
		}
		result, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 2, len(result.AllowedIPs))
	})

	t.Run("empty_strings_ignored", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Headers:  []string{"", "X-Real-IP", ""},
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"  ", "192.168.1.0/24", "  "}),
		}
		result, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 1, len(result.Headers))
		assert.Equal(t, 1, len(result.AllowedIPs))
	})
}

func TestRelyAuthAllowedIPs_Validate(t *testing.T) {
	t.Run("allowed_ip_in_subnet", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
		}
		allowedIPs, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
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
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
		}
		allowedIPs, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
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
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
		}
		allowedIPs, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{},
		}
		err = allowedIPs.Validate(body)
		assert.ErrorContains(t, err, ErrIPNotFound.Error())
	})

	t.Run("custom_header", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Headers:  []string{"X-Custom-IP"},
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
		}
		allowedIPs, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
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

func TestRelyAuthAllowedHostsFromConfig(t *testing.T) {
	t.Run("nil_config", func(t *testing.T) {
		result, err := RelyAuthAllowedHostsFromConfig(nil, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, ErrHostOriginRequired.Error())
		assert.Assert(t, result == nil)
	})

	t.Run("empty_patterns", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{}
		result, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, ErrHostOriginRequired.Error())
		assert.Assert(t, result == nil)
	})

	t.Run("valid_single_host", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"example.com"}),
		}
		result, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.AllowedHosts.Contains("example.com"))
	})

	t.Run("wildcard_host", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"*.example.com"}),
		}
		result, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.AllowedHosts.Contains("sub.example.com"))
		assert.Assert(t, !result.AllowedHosts.Contains("example.com"))
	})

	t.Run("all_hosts", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"*"}),
		}
		result, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.AllowedHosts.Contains("any-host.com"))
	})

	t.Run("multiple_hosts", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{
				"example.com",
				"*.test.com",
				"localhost",
			}),
		}
		result, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.AllowedHosts.Contains("example.com"))
		assert.Assert(t, result.AllowedHosts.Contains("api.test.com"))
		assert.Assert(t, result.AllowedHosts.Contains("localhost"))
	})

	t.Run("with_custom_headers", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Headers:  []string{"X-Forwarded-Host", "Host"},
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"example.com"}),
		}
		result, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 2, len(result.Headers))
		assert.Equal(t, "host", result.Headers[0])
		assert.Equal(t, "x-forwarded-host", result.Headers[1])
	})

	t.Run("case_insensitive", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"Example.COM", "TEST.com"}),
		}
		result, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.AllowedHosts.Contains("example.com"))
		assert.Assert(t, result.AllowedHosts.Contains("test.com"))
	})

	t.Run("duplicate_hosts_removed", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{
				"example.com",
				"example.com",
				"test.com",
			}),
		}
		result, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
	})

	t.Run("empty_strings_ignored", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Headers:  []string{"", "Origin", ""},
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"  ", "example.com", "  "}),
		}
		result, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 1, len(result.Headers))
	})
}

func TestRelyAuthAllowedHosts_Validate(t *testing.T) {
	t.Run("allowed_host", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"example.com"}),
		}
		allowedHosts, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"origin": "example.com",
			},
		}
		err = allowedHosts.Validate(body)
		assert.NilError(t, err)
	})

	t.Run("allowed_wildcard_host", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"*.example.com"}),
		}
		allowedHosts, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"origin": "api.example.com",
			},
		}
		err = allowedHosts.Validate(body)
		assert.NilError(t, err)
	})

	t.Run("disallowed_host", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"example.com"}),
		}
		allowedHosts, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"origin": "malicious.com",
			},
		}
		err = allowedHosts.Validate(body)
		assert.ErrorContains(t, err, ErrDisallowedOrigin.Error())
	})

	t.Run("origin_not_found", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"example.com"}),
		}
		allowedHosts, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{},
		}
		err = allowedHosts.Validate(body)
		assert.ErrorContains(t, err, ErrHostOriginRequired.Error())
	})

	t.Run("case_insensitive_validation", func(t *testing.T) {
		config := &RelyAuthHeaderAllowListSetting{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"example.com"}),
		}
		allowedHosts, err := RelyAuthAllowedHostsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"origin": "EXAMPLE.COM",
			},
		}
		err = allowedHosts.Validate(body)
		assert.NilError(t, err)
	})
}

func TestRelyAuthSecurityRulesFromConfig(t *testing.T) {
	t.Run("nil_config", func(t *testing.T) {
		result, err := RelyAuthSecurityRulesFromConfig(nil, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.AllowedIPs == nil)
		assert.Assert(t, result.AllowedHosts == nil)
	})

	t.Run("with_allowed_ips", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
		}
		result, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.AllowedIPs != nil)
		assert.Assert(t, result.AllowedHosts == nil)
	})

	t.Run("with_allowed_hosts", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedHosts: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"example.com"}),
			},
		}
		result, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.AllowedIPs == nil)
		assert.Assert(t, result.AllowedHosts != nil)
	})

	t.Run("with_both_rules", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
			AllowedHosts: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"example.com"}),
			},
		}
		result, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.AllowedIPs != nil)
		assert.Assert(t, result.AllowedHosts != nil)
	})
}

func TestRelyAuthSecurityRules_Authenticate(t *testing.T) {
	t.Run("no_rules", func(t *testing.T) {
		rules := &RelyAuthSecurityRules{}
		body := &AuthenticateRequestData{
			Headers: map[string]string{},
		}
		err := rules.Authenticate(body)
		assert.NilError(t, err)
	})

	t.Run("allowed_ip_only", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip": "192.168.1.100",
			},
		}
		err = rules.Authenticate(body)
		assert.NilError(t, err)
	})

	t.Run("disallowed_ip", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip": "10.0.0.1",
			},
		}
		err = rules.Authenticate(body)
		assert.ErrorContains(t, err, ErrDisallowedIP.Error())
	})

	t.Run("allowed_host_only", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedHosts: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"example.com"}),
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"origin": "example.com",
			},
		}
		err = rules.Authenticate(body)
		assert.NilError(t, err)
	})

	t.Run("disallowed_host", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedHosts: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"example.com"}),
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"origin": "malicious.com",
			},
		}
		err = rules.Authenticate(body)
		assert.ErrorContains(t, err, ErrDisallowedOrigin.Error())
	})

	t.Run("both_rules_pass", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
			AllowedHosts: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"example.com"}),
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip": "192.168.1.100",
				"origin":    "example.com",
			},
		}
		err = rules.Authenticate(body)
		assert.NilError(t, err)
	})

	t.Run("both_rules_host_fails", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
			AllowedHosts: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"example.com"}),
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip": "192.168.1.100",
				"origin":    "malicious.com",
			},
		}
		err = rules.Authenticate(body)
		assert.ErrorContains(t, err, ErrDisallowedOrigin.Error())
	})

	t.Run("both_rules_ip_fails", func(t *testing.T) {
		config := &RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
			AllowedHosts: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"example.com"}),
			},
		}
		rules, err := RelyAuthSecurityRulesFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip": "10.0.0.1",
				"origin":    "example.com",
			},
		}
		err = rules.Authenticate(body)
		assert.ErrorContains(t, err, ErrDisallowedIP.Error())
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

func TestGetOrigin(t *testing.T) {
	t.Run("from_origin_header", func(t *testing.T) {
		headers := map[string]string{
			"origin": "example.com",
		}
		origin := GetOrigin(headers)
		assert.Equal(t, "example.com", origin)
	})

	t.Run("case_insensitive", func(t *testing.T) {
		headers := map[string]string{
			"origin": "EXAMPLE.COM",
		}
		origin := GetOrigin(headers)
		assert.Equal(t, "example.com", origin)
	})

	t.Run("trim_whitespace", func(t *testing.T) {
		headers := map[string]string{
			"origin": "  example.com  ",
		}
		origin := GetOrigin(headers)
		assert.Equal(t, "example.com", origin)
	})

	t.Run("custom_header", func(t *testing.T) {
		headers := map[string]string{
			"x-forwarded-host": "api.example.com",
		}
		origin := GetOrigin(headers, "x-forwarded-host")
		assert.Equal(t, "api.example.com", origin)
	})

	t.Run("empty_headers", func(t *testing.T) {
		headers := map[string]string{}
		origin := GetOrigin(headers)
		assert.Equal(t, "", origin)
	})

	t.Run("empty_value", func(t *testing.T) {
		headers := map[string]string{
			"origin": "",
		}
		origin := GetOrigin(headers)
		assert.Equal(t, "", origin)
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
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
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
			AllowedIPs: &RelyAuthHeaderAllowListSetting{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
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

func (m *mockAuthenticator) Mode() AuthMode {
	return m.mode
}

func (m *mockAuthenticator) Close() error {
	return nil
}
