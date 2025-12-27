package jwt

import (
	"fmt"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/relychan/goutils"
	"github.com/relychan/rely-auth/auth/authmode"
)

// evalHasuraSessionVariables evaluates and transforms Hasura session variables for JWT claims:
// - The session variables must contain an x-hasura-default-role property and an x-hasura-allowed-roles array.
// - An x-hasura-role value can optionally be sent as a plain header in the request to indicate the role which should be used.
// - If x-hasura-role is not provided, the engine will use the x-hasura-default-role value from the JWT.
// See https://hasura.io/docs/3.0/auth/jwt/jwt-mode/#session-variable-requirements for more context.
func evalHasuraSessionVariables(result map[string]any, desiredRole string) (map[string]any, error) {
	rawAllowedRoles, ok := result[authmode.XHasuraAllowedRoles]
	if !ok || rawAllowedRoles == nil {
		return result, nil
	}

	allowedRoles, err := goutils.DecodeStringSlice(rawAllowedRoles)
	if err != nil {
		return nil, fmt.Errorf(
			"malformed %s; expected an array of strings: %w",
			authmode.XHasuraAllowedRoles,
			err,
		)
	}

	if desiredRole != "" {
		if !slices.Contains(allowedRoles, desiredRole) {
			return nil, goutils.NewForbiddenError(goutils.ErrorDetail{
				Header: authmode.XHasuraRole,
				Detail: fmt.Sprintf(
					"%s is not in the allowed roles %v",
					desiredRole,
					authmode.XHasuraAllowedRoles,
				),
			})
		}

		delete(result, authmode.XHasuraAllowedRoles)
		delete(result, authmode.XHasuraDefaultRole)

		result[authmode.XHasuraRole] = desiredRole

		return result, nil
	}

	var roleStr *string

	for _, roleKey := range []string{authmode.XHasuraRole, authmode.XHasuraDefaultRole} {
		rawRole, ok := result[roleKey]
		if !ok || rawRole == nil {
			continue
		}

		nullableRole, err := goutils.DecodeNullableString(rawRole)
		if err != nil {
			return nil, fmt.Errorf(
				"malformed %s; expected a string: %w",
				authmode.XHasuraDefaultRole,
				err,
			)
		}

		roleStr = nullableRole

		break
	}

	if roleStr == nil || *roleStr == "" {
		return nil, goutils.NewForbiddenError(goutils.ErrorDetail{
			Header: authmode.XHasuraDefaultRole,
			Detail: "value of x-hasura-default-role variable is empty",
		})
	}

	if !slices.Contains(allowedRoles, *roleStr) {
		return nil, goutils.NewForbiddenError(goutils.ErrorDetail{
			Header: authmode.XHasuraRole,
			Detail: fmt.Sprintf(
				"%s is not in the allowed roles %v",
				*roleStr,
				authmode.XHasuraAllowedRoles,
			),
		})
	}

	delete(result, authmode.XHasuraAllowedRoles)
	delete(result, authmode.XHasuraDefaultRole)

	result[authmode.XHasuraRole] = *roleStr

	return result, nil
}

func getSignatureAlgorithmsFromJWKS(keys []jose.JSONWebKey) []jose.SignatureAlgorithm {
	results := make([]jose.SignatureAlgorithm, 0, len(keys))

	for _, key := range keys {
		if key.Algorithm == "" {
			continue
		}

		alg := jose.SignatureAlgorithm(key.Algorithm)
		results = append(results, alg)
	}

	if len(results) == 0 {
		return []jose.SignatureAlgorithm{}
	}

	slices.Sort(results)

	return slices.Compact(results)
}
