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
	"strings"

	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/goutils"
)

var ipHeaders = []string{
	"cf-connecting-ip",
	"true-client-ip",
	"x-real-ip",
	"x-forwarded-for",
}

// GetClientIPsFromHeader gets the client IPs from request headers.
func GetClientIPsFromHeader(
	headers map[string]string,
	position ForwardedIPPosition,
	allowedHeaders ...string,
) []net.IP {
	if len(headers) == 0 {
		return nil
	}

	if len(allowedHeaders) == 0 {
		allowedHeaders = ipHeaders
	}

L:
	for _, name := range allowedHeaders {
		value, ok := headers[name]
		if !ok || value == "" {
			continue
		}

		rawIPs := strings.Split(value, ",")
		ips := make([]net.IP, 0, len(rawIPs))

		// Some headers (e.g., X-Forwarded-For) may contain a comma-separated list of IPs.
		for i, part := range rawIPs {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}

			ip := net.ParseIP(part)
			if ip != nil {
				ips = append(ips, ip)

				continue
			}

			if i == 0 || i == len(rawIPs)-1 {
				// invalid IP, ignore this header.
				continue L
			}
		}

		switch len(ips) {
		case 0:
			// no valid IP. ignore this header
		case 1:
			return ips
		default:
			switch position {
			case IPPositionEdge:
				return []net.IP{ips[0], ips[len(ips)-1]}
			case IPPositionLeftmost:
				return []net.IP{ips[0]}
			default:
				return []net.IP{ips[len(ips)-1]}
			}
		}
	}

	return nil
}

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

	tokenPrefix := rawToken[:prefixLength]

	if strings.ToLower(tokenPrefix) != scheme {
		return "", nil
	}

	return rawToken[prefixLength:], nil
}

// ValidateTokenLocation validates the token location.
func ValidateTokenLocation(
	tokenLocation authscheme.TokenLocation,
) (authscheme.TokenLocation, error) {
	err := tokenLocation.In.Validate()
	if err != nil {
		return tokenLocation, err
	}

	if tokenLocation.Name == "" {
		return tokenLocation, ErrLocationNameRequired
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
	return goutils.ToStringWithCustomTypeFormatter(value, "", func(anyValue any) (string, error) {
		switch typedValue := anyValue.(type) {
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
	})
}

func findTokenByLocation(
	body *AuthenticateRequestData,
	location *authscheme.TokenLocation,
) (string, error) {
	switch location.In {
	case authscheme.InHeader:
		for key, value := range body.Headers {
			if strings.ToLower(key) == location.Name {
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
			if strings.ToLower(cookie.Name) == location.Name {
				return cookie.Value, nil
			}
		}
	default:
	}

	return "", nil
}
