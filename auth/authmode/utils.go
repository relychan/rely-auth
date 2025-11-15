package authmode

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/relychan/gorestly/authc/authscheme"
)

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
	if value == nil {
		return "", nil
	}

	switch typedValue := value.(type) {
	case bool:
		return strconv.FormatBool(typedValue), nil
	case string:
		return typedValue, nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return fmt.Sprint(value), nil
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
