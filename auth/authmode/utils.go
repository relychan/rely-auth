package authmode

import (
	"encoding/json"
	"errors"
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
	"x-real-ip",
	"x-forwarded-for",
}

var originHeaders = []string{"origin"}

// ParseSubnet parses the subnet from a raw string.
func ParseSubnet(value string) (*net.IPNet, error) {
	if value == "" {
		return nil, ErrInvalidSubnet
	}

	if !strings.Contains(value, "/") {
		value += "/32"
	}

	_, subnet, err := net.ParseCIDR(value)
	if err != nil {
		return nil, err
	}

	return subnet, err
}

// GetClientIP get the client IP from request headers.
func GetClientIP(headers map[string]string, allowedHeaders ...string) (net.IP, error) {
	if len(headers) == 0 {
		return nil, ErrIPNotFound
	}

	if len(allowedHeaders) == 0 {
		allowedHeaders = ipHeaders
	}

	errs := []error{}

	for _, name := range allowedHeaders {
		value, ok := headers[name]
		if !ok || value == "" {
			continue
		}

		ip := net.ParseIP(value)
		if ip != nil {
			return ip, nil
		}

		errs = append(errs, fmt.Errorf("%s: %w", value, ErrInvalidIP))
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return nil, ErrInvalidIP
}

// GetOrigin get the origin header from request headers.
func GetOrigin(headers map[string]string, allowedHeaders ...string) string {
	if len(headers) == 0 {
		return ""
	}

	if len(allowedHeaders) == 0 {
		allowedHeaders = originHeaders
	}

	for _, name := range allowedHeaders {
		value, ok := headers[name]
		if !ok || value == "" {
			continue
		}

		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return strings.ToLower(trimmed)
		}
	}

	return ""
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
