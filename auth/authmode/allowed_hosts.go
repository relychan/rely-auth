package authmode

import (
	"fmt"
	"slices"
	"strings"

	"github.com/hasura/goenvconf"
	"github.com/relychan/goutils"
)

// RelyAuthAllowedHosts hold the allowed hosts security rule from the parsed config.
type RelyAuthAllowedHosts struct {
	Headers      []string
	AllowedHosts goutils.AllOrListWildcardString
}

// RelyAuthAllowedHostsFromConfig creates a [RelyAuthAllowedHosts] instance from config.
func RelyAuthAllowedHostsFromConfig(
	conf *RelyAuthHeaderAllowListSetting,
	getEnvFunc goenvconf.GetEnvFunc,
) (*RelyAuthAllowedHosts, error) {
	if conf == nil || conf.Patterns.IsZero() {
		return nil, ErrHostOriginRequired
	}

	if getEnvFunc == nil {
		getEnvFunc = goenvconf.GetOSEnv
	}

	patterns, err := conf.Patterns.GetCustom(getEnvFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to get allowed hosts: %w", err)
	}

	if len(patterns) == 0 {
		return nil, ErrHostOriginRequired
	}

	for i, p := range patterns {
		patterns[i] = strings.ToLower(strings.TrimSpace(p))
	}

	slices.Sort(patterns)

	patterns = slices.Compact(patterns)

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

	result := &RelyAuthAllowedHosts{
		Headers:      slices.Compact(headers),
		AllowedHosts: goutils.NewAllOrListWildcardStringFromStrings(patterns),
	}

	return result, nil
}

// Validate checks if the request satisfies the security rule.
func (ah *RelyAuthAllowedHosts) Validate(body *AuthenticateRequestData) error {
	origin := GetOrigin(body.Headers)
	if origin == "" {
		return ErrHostOriginRequired
	}

	if ah.AllowedHosts.Contains(origin) {
		return nil
	}

	return ErrDisallowedOrigin
}
