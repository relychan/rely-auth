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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/hasura/goenvconf"
	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/goutils"
)

// GetAuthModeHeader gets the authentication mode from request headers.
// Note that headers must be converted to a string map with keys in lower-case.
func GetAuthModeHeader(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}

	authMode, ok := headers[XRelyAuthMode]
	if ok && authMode != "" {
		return authMode
	}

	return headers[XHasuraAuthMode]
}

// FindAuthTokenByLocation finds the authentication token or api key from the request.
func FindAuthTokenByLocation(
	body *AuthenticateRequestData,
	location *authscheme.TokenLocation,
) (string, error) {
	rawToken, err := findTokenByLocation(body, location)
	if err != nil {
		return "", err
	}

	if rawToken == "" {
		return "", ErrAuthTokenNotFound
	}

	if location.Scheme == "" {
		return rawToken, nil
	}

	scheme := location.Scheme + " "
	prefixLength := len(scheme)

	if len(rawToken) <= prefixLength {
		return "", nil
	}

	if !strings.EqualFold(rawToken[:prefixLength], scheme) {
		return "", nil
	}

	return rawToken[prefixLength:], nil
}

// ValidateTokenLocation validates the token location.
func ValidateTokenLocation(
	tokenLocation authscheme.TokenLocation,
) (authscheme.TokenLocation, error) {
	err := tokenLocation.Validate()
	if err != nil {
		return tokenLocation, err
	}

	return authscheme.TokenLocation{
		In:     tokenLocation.In,
		Name:   strings.TrimSpace(strings.ToLower(tokenLocation.Name)),
		Scheme: strings.TrimSpace(strings.ToLower(tokenLocation.Scheme)),
	}, nil
}

// SerializeSessionVariablesHasuraGraphQLEngine serializes session variables to be compatible with [Hasura GraphQL Engine].
//
// [Hasura GraphQL Engine]: https://hasura.io/docs/2.0/auth/authorization/roles-variables/#type-formats-of-session-variables
func SerializeSessionVariablesHasuraGraphQLEngine(
	sessionVariables map[string]any,
) (map[string]string, error) {
	result := make(map[string]string)

	for key, value := range sessionVariables {
		serializedValue, err := serializeSessionVariableHasuraGraphQLEngine(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}

		result[key] = serializedValue
	}

	return result, nil
}

func serializeSessionVariableHasuraGraphQLEngine(value any) (string, error) {
	scalarString, ok := goutils.FormatScalar(value)
	if ok {
		return scalarString, nil
	}

	switch typedValue := value.(type) {
	case []any:
		results := make([]string, 0, len(typedValue))

		for i, item := range typedValue {
			result, err := serializeSessionVariableHasuraGraphQLEngine(item)
			if err != nil {
				return "", fmt.Errorf("%d: %w", i, err)
			}

			if result != "" {
				results = append(results, result)
			}
		}

		return "{" + strings.Join(results, ",") + "}", nil
	default:
		jsonValue, err := json.Marshal(value)
		if err != nil {
			return "", err
		}

		return string(jsonValue), nil
	}
}

func findTokenByLocation(
	body *AuthenticateRequestData,
	location *authscheme.TokenLocation,
) (string, error) {
	switch location.In {
	case authscheme.InHeader:
		for key, value := range body.Headers {
			if strings.EqualFold(key, location.Name) {
				return value, nil
			}
		}
	case authscheme.InQuery:
		if body.URL == "" || body.URL == "/" {
			return "", nil
		}

		_, rawQuery, found := strings.Cut(body.URL, "?")
		if !found || rawQuery == "" {
			return "", nil
		}

		queries, err := url.ParseQuery(rawQuery)
		if err != nil {
			return "", err
		}

		return queries.Get(location.Name), nil
	case authscheme.InCookie:
		if len(body.Headers) == 0 {
			return "", nil
		}

		rawCookies := body.Headers["cookie"]
		if rawCookies == "" {
			return "", nil
		}

		cookies, err := http.ParseCookie(rawCookies)
		if err != nil {
			return "", err
		}

		for _, cookie := range cookies {
			if strings.EqualFold(cookie.Name, location.Name) {
				return cookie.Value, nil
			}
		}
	default:
	}

	return "", nil
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

	return results, nil
}
