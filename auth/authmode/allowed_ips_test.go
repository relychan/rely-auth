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
	"net"
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

func TestClientIPLocation_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		loc      ClientIPLocation
		expected bool
	}{
		{"x_forwarded_for", ClientIPFromXForwardedFor, true},
		{"header", ClientIPFromHeader, true},
		{"remote_addr", ClientIPFromRemoteAddr, true},
		{"out_of_range", ClientIPLocation(3), false},
		{"max_uint8", ClientIPLocation(255), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.loc.IsValid())
		})
	}
}

func TestClientIPLocation_String(t *testing.T) {
	tests := []struct {
		name     string
		loc      ClientIPLocation
		expected string
	}{
		{"x_forwarded_for", ClientIPFromXForwardedFor, "x_forwarded_for"},
		{"header", ClientIPFromHeader, "header"},
		{"remote_addr", ClientIPFromRemoteAddr, "remote_addr"},
		{"invalid_returns_empty", ClientIPLocation(99), ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.loc.String())
		})
	}
}

func TestClientIPLocation_MarshalText(t *testing.T) {
	loc := ClientIPFromHeader
	data, err := loc.MarshalText()
	require.NoError(t, err)
	assert.Equal(t, "header", string(data))
}

func TestClientIPLocation_UnmarshalText(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		var loc ClientIPLocation
		require.NoError(t, loc.UnmarshalText([]byte("header")))
		assert.Equal(t, ClientIPFromHeader, loc)
	})

	t.Run("invalid", func(t *testing.T) {
		var loc ClientIPLocation
		err := loc.UnmarshalText([]byte("bogus"))
		assert.ErrorContains(t, err, ErrInvalidClientIPLocation.Error())
	})
}

func TestClientIPLocation_MarshalUnmarshalJSON(t *testing.T) {
	t.Run("marshal_remote_addr", func(t *testing.T) {
		data, err := ClientIPFromRemoteAddr.MarshalJSON()
		require.NoError(t, err)
		assert.Equal(t, `"remote_addr"`, string(data))
	})

	t.Run("unmarshal_x_forwarded_for", func(t *testing.T) {
		var loc ClientIPLocation
		require.NoError(t, loc.UnmarshalJSON([]byte(`"x_forwarded_for"`)))
		assert.Equal(t, ClientIPFromXForwardedFor, loc)
	})

	t.Run("unmarshal_invalid", func(t *testing.T) {
		var loc ClientIPLocation
		err := loc.UnmarshalJSON([]byte(`"unknown"`))
		assert.ErrorContains(t, err, ErrInvalidClientIPLocation.Error())
	})
}

func TestParseClientIPLocation(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    ClientIPLocation
		expectError bool
	}{
		{"x_forwarded_for", "x_forwarded_for", ClientIPFromXForwardedFor, false},
		{"header", "header", ClientIPFromHeader, false},
		{"remote_addr", "remote_addr", ClientIPFromRemoteAddr, false},
		{"invalid_value", "invalid", 255, true},
		{"empty_string", "", 255, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			loc, err := ParseClientIPLocation(tc.input)
			if tc.expectError {
				assert.ErrorContains(t, err, ErrInvalidClientIPLocation.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, loc)
			}
		})
	}
}

func TestAllowedIPsFromConfig_LocationAndHeaders(t *testing.T) {
	t.Run("header_location_requires_headers", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Location: ClientIPFromHeader,
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, ErrClientIPHeaderRequired.Error())
		assert.Nil(t, result)
	})

	t.Run("header_location_all_empty_headers_rejected", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Location: ClientIPFromHeader,
			Headers:  []string{"", "   "},
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.ErrorContains(t, err, ErrClientIPHeaderRequired.Error())
		assert.Nil(t, result)
	})

	t.Run("duplicate_headers_compacted", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Location: ClientIPFromHeader,
			Headers:  []string{"X-Real-IP", "x-real-ip", "X-Real-IP"},
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{"10.0.0.0/8"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)
		assert.Equal(t, []string{"x-real-ip"}, result.Headers)
	})

	t.Run("xff_with_trusted_proxy_prefixes", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Location:               ClientIPFromXForwardedFor,
			TrustedProxyIPPrefixes: []string{"10.0.0.0/8", "172.16.0.0/12"},
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)
		require.Len(t, result.TrustedProxyIPPrefixes, 2)
	})

	t.Run("xff_empty_trusted_proxy_prefix_skipped", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Location:               ClientIPFromXForwardedFor,
			TrustedProxyIPPrefixes: []string{"", "10.0.0.0/8", "   "},
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)
		assert.Len(t, result.TrustedProxyIPPrefixes, 1)
	})

	t.Run("xff_invalid_trusted_proxy_prefix", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Location:               ClientIPFromXForwardedFor,
			TrustedProxyIPPrefixes: []string{"not-a-cidr"},
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("remote_addr_location", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			Location: ClientIPFromRemoteAddr,
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{"192.168.1.0/24"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)
		assert.Equal(t, ClientIPFromRemoteAddr, result.Location)
	})

	t.Run("nil_getenvfunc_defaults_to_os", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Include: new(goenvconf.NewEnvStringSliceValue([]string{"10.0.0.1"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, nil)
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("exclude_only_config", func(t *testing.T) {
		config := &RelyAuthIPAllowListConfig{
			RelyAuthAllowListConfig: RelyAuthAllowListConfig{
				Exclude: new(goenvconf.NewEnvStringSliceValue([]string{"10.0.0.0/8"})),
			},
		}
		result, err := AllowedIPsFromConfig(config, goenvconf.GetOSEnv)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.BlockedIPRanges, 1)
	})
}

func TestRelyAuthIPAllowList_GetClientIPs(t *testing.T) {
	t.Run("nil_data_returns_error", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{Location: ClientIPFromHeader, Headers: []string{"x-real-ip"}}
		ip, err := rai.GetClientIPs(nil)
		assert.Nil(t, ip)
		assert.ErrorContains(t, err, ErrIPNotFound.Error())
	})

	t.Run("header_no_headers_map", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{Location: ClientIPFromHeader, Headers: []string{"x-real-ip"}}
		ip, err := rai.GetClientIPs(&AuthenticateRequestData{})
		assert.Nil(t, ip)
		assert.ErrorContains(t, err, ErrIPNotFound.Error())
	})

	t.Run("header_missing_header_key", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{Location: ClientIPFromHeader, Headers: []string{"x-real-ip"}}
		ip, err := rai.GetClientIPs(&AuthenticateRequestData{Headers: map[string]string{}})
		assert.Nil(t, ip)
		assert.ErrorContains(t, err, ErrIPNotFound.Error())
	})

	t.Run("header_valid_ip", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{Location: ClientIPFromHeader, Headers: []string{"x-real-ip"}}
		ip, err := rai.GetClientIPs(&AuthenticateRequestData{
			Headers: map[string]string{"x-real-ip": "1.2.3.4"},
		})
		require.NoError(t, err)
		assert.Equal(t, "1.2.3.4", ip.String())
	})

	t.Run("header_first_matching_header_wins", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{
			Location: ClientIPFromHeader,
			Headers:  []string{"cf-connecting-ip", "x-real-ip"},
		}
		ip, err := rai.GetClientIPs(&AuthenticateRequestData{
			Headers: map[string]string{
				"cf-connecting-ip": "5.6.7.8",
				"x-real-ip":        "1.2.3.4",
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "5.6.7.8", ip.String())
	})

	t.Run("header_multi_value_last_wins", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{Location: ClientIPFromHeader, Headers: []string{"x-client-ip"}}
		ip, err := rai.GetClientIPs(&AuthenticateRequestData{
			Headers: map[string]string{"x-client-ip": "1.2.3.4, 9.9.9.9"},
		})
		require.NoError(t, err)
		assert.Equal(t, "9.9.9.9", ip.String())
	})

	t.Run("xff_no_headers_map", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{Location: ClientIPFromXForwardedFor}
		ip, err := rai.GetClientIPs(&AuthenticateRequestData{})
		assert.Nil(t, ip)
		assert.ErrorContains(t, err, ErrIPNotFound.Error())
	})

	t.Run("remote_addr_empty", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{Location: ClientIPFromRemoteAddr}
		ip, err := rai.GetClientIPs(&AuthenticateRequestData{RemoteAddr: ""})
		assert.Nil(t, ip)
		assert.ErrorContains(t, err, ErrIPNotFound.Error())
	})

	t.Run("remote_addr_host_port", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{Location: ClientIPFromRemoteAddr}
		ip, err := rai.GetClientIPs(&AuthenticateRequestData{RemoteAddr: "192.168.1.10:12345"})
		require.NoError(t, err)
		assert.Equal(t, "192.168.1.10", ip.String())
	})

	t.Run("remote_addr_bare_ip", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{Location: ClientIPFromRemoteAddr}
		ip, err := rai.GetClientIPs(&AuthenticateRequestData{RemoteAddr: "10.0.0.5"})
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.5", ip.String())
	})

	t.Run("remote_addr_invalid_ip", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{Location: ClientIPFromRemoteAddr}
		ip, err := rai.GetClientIPs(&AuthenticateRequestData{RemoteAddr: "not-an-ip"})
		assert.Nil(t, ip)
		assert.ErrorContains(t, err, ErrInvalidIP.Error())
	})
}

func TestParseXFFAddr(t *testing.T) {
	mustParseCIDR := func(s string) *net.IPNet {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("failed to parse CIDR %s: %v", s, err)
		}

		return n
	}

	t.Run("no_proxies_returns_parseHeaderAddr", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{}
		ip, err := rai.parseXFFAddr("1.2.3.4")
		require.NoError(t, err)
		assert.Equal(t, "1.2.3.4", ip.String())
	})

	t.Run("num_trusted_proxies_1_single_entry", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{NumTrustedProxies: 1}
		ip, err := rai.parseXFFAddr("1.2.3.4")
		require.NoError(t, err)
		assert.Equal(t, "1.2.3.4", ip.String())
	})

	t.Run("num_trusted_proxies_1_chain", func(t *testing.T) {
		// client(1.2.3.4) -> proxy(10.0.0.1) -> this server; XFF: "1.2.3.4, 10.0.0.1"
		// With 1 trusted proxy, we return the rightmost entry (10.0.0.1).
		rai := &RelyAuthIPAllowList{NumTrustedProxies: 1}
		ip, err := rai.parseXFFAddr("1.2.3.4, 10.0.0.1")
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.1", ip.String())
	})

	t.Run("num_trusted_proxies_2_chain", func(t *testing.T) {
		// XFF: "client, proxy1, proxy2" — with 2 trusted proxies, we return the middle entry (proxy1).
		rai := &RelyAuthIPAllowList{NumTrustedProxies: 2}
		ip, err := rai.parseXFFAddr("5.5.5.5, 10.0.0.1, 10.0.0.2")
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.1", ip.String())
	})

	t.Run("trusted_proxy_prefixes_stops_at_untrusted", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{
			TrustedProxyIPPrefixes: []*net.IPNet{mustParseCIDR("10.0.0.0/8")},
		}
		// XFF: "client(5.5.5.5), trusted-proxy(10.0.0.1)"
		ip, err := rai.parseXFFAddr("5.5.5.5, 10.0.0.1")
		require.NoError(t, err)
		assert.Equal(t, "5.5.5.5", ip.String())
	})

	t.Run("trusted_proxy_prefixes_all_trusted_returns_leftmost", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{
			TrustedProxyIPPrefixes: []*net.IPNet{mustParseCIDR("10.0.0.0/8")},
		}
		// All hops are trusted — only one non-trusted found nowhere, returns not-found.
		ip, err := rai.parseXFFAddr("10.0.0.2, 10.0.0.3")
		assert.Nil(t, ip)
		assert.ErrorContains(t, err, ErrIPNotFound.Error())
	})

	t.Run("empty_xff_value", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{NumTrustedProxies: 1}
		ip, err := rai.parseXFFAddr("")
		assert.Nil(t, ip)
		assert.Error(t, err, ErrIPNotFound)
	})

	t.Run("whitespace_only_entries_skipped", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{NumTrustedProxies: 1}
		ip, err := rai.parseXFFAddr("  , 1.2.3.4")
		require.NoError(t, err)
		assert.Equal(t, "1.2.3.4", ip.String())
	})

	t.Run("invalid_ip_in_chain_returns_error", func(t *testing.T) {
		rai := &RelyAuthIPAllowList{NumTrustedProxies: 1}
		ip, err := rai.parseXFFAddr("1.2.3.4, not-an-ip")
		assert.Nil(t, ip)
		assert.ErrorContains(t, err, ErrInvalidIP.Error())
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
