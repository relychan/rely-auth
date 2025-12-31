package authmode

import (
	"fmt"
	"strings"

	"github.com/hasura/goenvconf"
	"github.com/relychan/goutils"
)

// RelyAuthAllowListMatcherRule represents a matcher rule for a field.
type RelyAuthAllowListMatcherRule struct {
	// List of regular expressions that are allowed to access.
	Include []*goutils.RegexpMatcher
	// List of regular expressions that are denied to access.
	Exclude []*goutils.RegexpMatcher
}

// AllowListMatcherRuleFromConfig creates an allow list matcher rule from config.
func AllowListMatcherRuleFromConfig(
	conf RelyAuthAllowListConfig,
	getEnvFunc goenvconf.GetEnvFunc,
) (*RelyAuthAllowListMatcherRule, error) {
	include, err := regexpMatchersFromConfig(conf.Include, getEnvFunc)
	if err != nil {
		return nil, fmt.Errorf("include: %w", err)
	}

	exclude, err := regexpMatchersFromConfig(conf.Exclude, getEnvFunc)
	if err != nil {
		return nil, fmt.Errorf("exclude: %w", err)
	}

	result := &RelyAuthAllowListMatcherRule{
		Include: include,
		Exclude: exclude,
	}

	return result, nil
}

// IsValid checks if the request satisfies the security rule.
func (hr RelyAuthAllowListMatcherRule) IsValid(value string) bool {
	for _, rule := range hr.Exclude {
		if rule.MatchString(value) {
			return false
		}
	}

	if len(hr.Include) == 0 {
		return true
	}

	for _, rule := range hr.Include {
		if rule.MatchString(value) {
			return true
		}
	}

	return false
}

// RelyAuthHeaderRules represents a map of header rules.
type RelyAuthHeaderRules map[string]RelyAuthAllowListMatcherRule

// HeaderRulesFromConfig creates a header map with expression matchers from config.
func HeaderRulesFromConfig(
	conf map[string]RelyAuthAllowListConfig,
	getEnvFunc goenvconf.GetEnvFunc,
) (RelyAuthHeaderRules, error) {
	results := make(map[string]RelyAuthAllowListMatcherRule)

	for key, envVar := range conf {
		rule, err := AllowListMatcherRuleFromConfig(envVar, getEnvFunc)
		if err != nil {
			return nil, fmt.Errorf("failed to parse header rule %s: %w", key, err)
		}

		results[strings.ToLower(key)] = *rule
	}

	return results, nil
}

// Validate checks if the request satisfies the security rule.
func (hr RelyAuthHeaderRules) Validate(body *AuthenticateRequestData) error {
	if len(hr) > 0 && len(body.Headers) == 0 {
		return fmt.Errorf("%w: headers are required", ErrInvalidHeader)
	}

	for key, rule := range hr {
		value, ok := body.Headers[key]
		if !ok {
			return fmt.Errorf("%w: value of header %s does not exist", ErrInvalidHeader, key)
		}

		if !rule.IsValid(value) {
			return fmt.Errorf(
				"%w: value of header %s does not satisfy security rules",
				ErrInvalidHeader,
				key,
			)
		}
	}

	return nil
}

func regexpMatchersFromConfig(
	list *goenvconf.EnvStringSlice,
	getEnvFunc goenvconf.GetEnvFunc,
) ([]*goutils.RegexpMatcher, error) {
	if list == nil {
		return nil, nil
	}

	if getEnvFunc == nil {
		getEnvFunc = goenvconf.GetOSEnv
	}

	rawExpressions, err := list.GetCustom(getEnvFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to get matcher rules: %w", err)
	}

	if len(rawExpressions) == 0 {
		return nil, nil
	}

	matchers := make([]*goutils.RegexpMatcher, len(rawExpressions))

	for i, expr := range rawExpressions {
		re, err := goutils.NewRegexpMatcher(expr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse matcher rule: %w", err)
		}

		matchers[i] = re
	}

	return matchers, nil
}
