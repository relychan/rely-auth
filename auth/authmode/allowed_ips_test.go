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
	"testing"

	"github.com/hasura/goenvconf"
	"github.com/relychan/goutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRelyAuthAllowedIPsFromConfig(t *testing.T) {
	t.Run("nil_config", func(t *testing.T) {
		result, err := AllowedIPsFromConfig(nil, goenvconf.GetOSEnv)
		require.ErrorContains(t, err, ErrEmptyAllowedIPs.Error())
		assert.True(t, result == nil)
	})

	t.Run("empty_patterns", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, ErrEmptyAllowedIPs.Error())
		assert.True(t, result == nil)
	})

	t.Run("valid_single_ip", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.100"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)
		assert.True(t, result != nil)
		assert.Equal(t, 1, len(result.AllowedIPRanges))
		assert.Equal(t, "192.168.1.100/32", result.AllowedIPRanges[0].String())
	})

	t.Run("valid_subnet", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)
		assert.True(t, result != nil)
		assert.Equal(t, 1, len(result.AllowedIPRanges))
		assert.Equal(t, "192.168.1.0/24", result.AllowedIPRanges[0].String())
	})

	t.Run("multiple_ips_and_subnets", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{
					"192.168.1.0/24",
					"10.0.0.1",
					"172.16.0.0/16",
				})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)
		assert.True(t, result != nil)
		assert.Equal(t, 3, len(result.AllowedIPRanges))
	})

	t.Run("with_custom_headers", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Headers:  []string{"X-Real-IP", "X-Forwarded-For"},
			Location: ClientIPFromHeader,
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)
		require.True(t, result != nil)
		require.Equal(t, 2, len(result.Headers))
		// Headers are sorted alphabetically
		require.Equal(t, "x-forwarded-for", result.Headers[0])
		require.Equal(t, "x-real-ip", result.Headers[1])
	})

	t.Run("invalid_ip", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{"invalid-ip"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.True(t, err != nil)
		assert.True(t, result == nil)
	})

	t.Run("duplicate_ips_removed", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{
					"192.168.1.0/24",
					"192.168.1.0/24",
					"10.0.0.1",
				})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)
		assert.True(t, result != nil)
		assert.Equal(t, 2, len(result.AllowedIPRanges))
	})

	t.Run("empty_strings_ignored", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Headers:  []string{"", "X-Real-IP", ""},
			Location: ClientIPFromHeader,
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{"  ", "192.168.1.0/24", "  "})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)
		require.True(t, result != nil)
		require.Equal(t, 1, len(result.Headers))
		require.Equal(t, 1, len(result.AllowedIPRanges))
	})
}

func TestRelyAuthAllowedIPs_Validate(t *testing.T) {
	t.Run("allowed_ip_in_subnet", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Headers:  []string{"X-Real-IP"},
			Location: ClientIPFromHeader,
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{
					"192.168.1.0/24",
				})),
			},
		}
		allowedIPs, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip": "192.168.1.100",
			},
		}
		err = allowedIPs.Validate(body)
		require.NoError(t, err)
	})

	t.Run("disallowed_ip", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Headers:  []string{"X-Real-IP"},
			Location: ClientIPFromHeader,
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{
					"192.168.1.0/24",
				})),
			},
		}
		allowedIPs, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-real-ip": "10.0.0.1",
			},
		}
		err = allowedIPs.Validate(body)
		assert.ErrorContains(t, err, goutils.ErrBlockedIP.Error())
	})

	t.Run("ip_not_found", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{
					"192.168.1.0/24",
				})),
			},
		}
		allowedIPs, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{},
		}
		err = allowedIPs.Validate(body)
		assert.ErrorContains(t, err, ErrIPNotFound.Error())
	})

	t.Run("custom_header", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Headers:  []string{"X-Custom-IP"},
			Location: ClientIPFromHeader,
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{
					"192.168.1.0/24",
				})),
			},
		}
		allowedIPs, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)

		body := &AuthenticateRequestData{
			Headers: map[string]string{
				"x-custom-ip": "192.168.1.50",
			},
		}
		err = allowedIPs.Validate(body)
		require.NoError(t, err)
	})
}
