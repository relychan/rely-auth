package authmode

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/hasura/goenvconf"
	"github.com/relychan/goutils"
)

// RelyAuthIPAllowList holds security rules of the IP allow list from the parsed config.
type RelyAuthIPAllowList struct {
	goutils.ValidateIPOptions

	Headers []string
}

// AllowedIPsFromConfig creates a [RelyAuthIPAllowList] instance from config.
func AllowedIPsFromConfig(
	conf *RelyAuthIPAllowListConfig,
	getEnvFunc goenvconf.GetEnvFunc,
) (*RelyAuthIPAllowList, error) {
	if conf == nil ||
		((conf.Include == nil || conf.Include.IsZero()) && (conf.Exclude == nil || conf.Exclude.IsZero())) {
		return nil, ErrEmptyAllowedIPs
	}

	if getEnvFunc == nil {
		getEnvFunc = goenvconf.GetOSEnv
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
		headers = slices.Compact(headers)
	}

	include, err := parseEnvSubnets(conf.Include, getEnvFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse allowed IP: %w", err)
	}

	exclude, err := parseEnvSubnets(conf.Exclude, getEnvFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse disallowed IP: %w", err)
	}

	result := &RelyAuthIPAllowList{
		ValidateIPOptions: goutils.ValidateIPOptions{
			AllowedIPRanges: include,
			BlockedIPRanges: exclude,
			PublicIPOnly:    conf.PublicOnly,
		},
		Headers: headers,
	}

	return result, nil
}

// Validate checks if the request satisfies the security rule.
func (ai *RelyAuthIPAllowList) Validate(ctx context.Context, body *AuthenticateRequestData) error {
	clientIPs := GetClientIPsFromHeader(body.Headers, ai.Headers...)
	if len(clientIPs) == 0 {
		return ErrIPNotFound
	}

	for _, ip := range clientIPs {
		err := goutils.ValidateIP(ctx, ip, ai.ValidateIPOptions)
		if err != nil {
			return err
		}
	}

	return nil
}

func parseEnvSubnets(
	list *goenvconf.EnvStringSlice,
	getEnvFunc goenvconf.GetEnvFunc,
) ([]*net.IPNet, error) {
	if list == nil {
		return nil, nil
	}

	patterns, err := list.GetCustom(getEnvFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to get allowed IP patterns: %w", err)
	}

	if len(patterns) == 0 {
		return nil, nil
	}

	slices.Sort(patterns)

	patterns = slices.Compact(patterns)
	results := make([]*net.IPNet, 0, len(patterns))

	for _, pattern := range patterns {
		trimmed := strings.TrimSpace(pattern)

		if trimmed == "" {
			continue
		}

		ip, err := goutils.ParseSubnet(trimmed)
		if err != nil {
			return nil, err
		}

		results = append(results, ip)
	}

	return slices.Clip(results), nil
}
