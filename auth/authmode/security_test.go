package authmode

import (
	"context"
	"testing"

	"github.com/hasura/goenvconf"
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
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
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
			Headers:  []string{"x-forwarded-for"},
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
		}
		b := RelyAuthIPAllowListConfig{
			Headers:  []string{"x-forwarded-for"},
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
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
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
		}
		b := RelyAuthIPAllowListConfig{
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
			AllowedIPs: nil,
		}
		assert.Assert(t, config.IsZero())
	})

	t.Run("zero_empty_settings", func(t *testing.T) {
		config := RelyAuthSecurityRulesConfig{
			AllowedIPs:  &RelyAuthIPAllowListConfig{},
			HeaderRules: make(map[string]goenvconf.EnvStringSlice),
		}
		assert.Assert(t, config.IsZero())
	})

	t.Run("non_zero_with_allowed_ips", func(t *testing.T) {
		config := RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
		}
		assert.Assert(t, !config.IsZero())
	})

	t.Run("non_zero_with_allowed_hosts", func(t *testing.T) {
		config := RelyAuthSecurityRulesConfig{
			HeaderRules: map[string]goenvconf.EnvStringSlice{
				"Test": goenvconf.NewEnvStringSliceValue([]string{"*.example.com"}),
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
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
		}
		b := RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
		}
		assert.Assert(t, a.Equal(b))
	})

	t.Run("not_equal_different_ips", func(t *testing.T) {
		a := RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
				Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
			},
		}
		b := RelyAuthSecurityRulesConfig{
			AllowedIPs: &RelyAuthIPAllowListConfig{
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
		config := &RelyAuthIPAllowListConfig{}
		result, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, ErrEmptyAllowedIPs.Error())
		assert.Assert(t, result == nil)
	})

	t.Run("valid_single_ip", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.100"}),
		}
		result, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 1, len(result.AllowedIPs))
		assert.Equal(t, "192.168.1.100/32", result.AllowedIPs[0].String())
	})

	t.Run("valid_subnet", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"}),
		}
		result, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Equal(t, 1, len(result.AllowedIPs))
		assert.Equal(t, "192.168.1.0/24", result.AllowedIPs[0].String())
	})

	t.Run("multiple_ips_and_subnets", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
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
		config := &RelyAuthIPAllowListConfig{
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
		config := &RelyAuthIPAllowListConfig{
			Patterns: goenvconf.NewEnvStringSliceValue([]string{"invalid-ip"}),
		}
		result, err := RelyAuthAllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.Assert(t, err != nil)
		assert.Assert(t, result == nil)
	})

	t.Run("duplicate_ips_removed", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
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
		config := &RelyAuthIPAllowListConfig{
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
		config := &RelyAuthIPAllowListConfig{
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
		config := &RelyAuthIPAllowListConfig{
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
		config := &RelyAuthIPAllowListConfig{
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
		config := &RelyAuthIPAllowListConfig{
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
			AllowedIPs: &RelyAuthIPAllowListConfig{
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
