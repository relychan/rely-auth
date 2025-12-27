package authmode

import (
	"fmt"
	"strings"

	"github.com/hasura/goenvconf"
	"github.com/relychan/goutils"
)

// RelyAuthHeaderRules represents a map of header rules.
type RelyAuthHeaderRules map[string][]*goutils.RegexpMatcher

// RelyAuthHeaderRulesFromConfig creates a header map with expression matchers from config.
func RelyAuthHeaderRulesFromConfig(
	conf map[string]goenvconf.EnvStringSlice,
	getEnvFunc goenvconf.GetEnvFunc,
) (RelyAuthHeaderRules, error) {
	results := make(map[string][]*goutils.RegexpMatcher)

	if getEnvFunc == nil {
		getEnvFunc = goenvconf.GetOSEnv
	}

	for key, envVar := range conf {
		rawExpressions, err := envVar.GetCustom(getEnvFunc)
		if err != nil {
			return nil, fmt.Errorf("failed to get header rule %s: %w", key, err)
		}

		if len(rawExpressions) == 0 {
			continue
		}

		matchers := make([]*goutils.RegexpMatcher, len(rawExpressions))

		for i, expr := range rawExpressions {
			re, err := goutils.NewRegexpMatcher(expr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse header rule %s: %w", key, err)
			}

			matchers[i] = re
		}

		results[strings.ToLower(key)] = matchers
	}

	return results, nil
}

// Validate checks if the request satisfies the security rule.
func (hr RelyAuthHeaderRules) Validate(body *AuthenticateRequestData) error {
	if len(hr) > 0 && len(body.Headers) == 0 {
		return fmt.Errorf("%w: headers are required", ErrInvalidHeader)
	}

L:
	for key, rules := range hr {
		value, ok := body.Headers[key]
		if !ok {
			return fmt.Errorf("%w: value of header %s does not exist", ErrInvalidHeader, key)
		}

		for _, rule := range rules {
			if rule.MatchString(value) {
				continue L
			}
		}

		return fmt.Errorf("%w: value of header %s does not satisfy security rules", ErrInvalidHeader, key)
	}

	return nil
}
