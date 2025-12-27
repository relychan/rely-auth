package authmode

import (
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/hasura/goenvconf"
)

// RelyAuthAllowedIPs hold the allowed IPs security rule from the parsed config.
type RelyAuthAllowedIPs struct {
	Headers    []string
	AllowedIPs []*net.IPNet
}

// RelyAuthAllowedIPsFromConfig creates a [RelyAuthAllowedIPs] instance from config.
func RelyAuthAllowedIPsFromConfig(
	conf *RelyAuthIPAllowListConfig,
	getEnvFunc goenvconf.GetEnvFunc,
) (*RelyAuthAllowedIPs, error) {
	if conf == nil || conf.Patterns.IsZero() {
		return nil, ErrEmptyAllowedIPs
	}

	if getEnvFunc == nil {
		getEnvFunc = goenvconf.GetOSEnv
	}

	patterns, err := conf.Patterns.GetCustom(getEnvFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to get allowed IP patterns: %w", err)
	}

	if len(patterns) == 0 {
		return nil, ErrEmptyAllowedIPs
	}

	slices.Sort(patterns)

	patterns = slices.Compact(patterns)
	allowedIPs := make([]*net.IPNet, 0, len(patterns))

	for _, pattern := range patterns {
		trimmed := strings.TrimSpace(pattern)

		if trimmed == "" {
			continue
		}

		ip, err := ParseSubnet(trimmed)
		if err != nil {
			return nil, err
		}

		allowedIPs = append(allowedIPs, ip)
	}

	var headers []string

	if len(conf.Headers) > 0 {
		headers = make([]string, 0, len(conf.Headers))

		for _, header := range conf.Headers {
			if header == "" {
				continue
			}

			headers = append(headers, strings.ToLower(header))
		}

		slices.Sort(headers)
	}

	result := &RelyAuthAllowedIPs{
		Headers:    slices.Compact(headers),
		AllowedIPs: slices.Compact(allowedIPs),
	}

	return result, nil
}

// Validate checks if the request satisfies the security rule.
func (ai *RelyAuthAllowedIPs) Validate(body *AuthenticateRequestData) error {
	clientIP, err := GetClientIP(body.Headers, ai.Headers...)
	if err != nil {
		return err
	}

	for _, subnet := range ai.AllowedIPs {
		if subnet.Contains(clientIP) {
			return nil
		}
	}

	return ErrDisallowedIP
}
