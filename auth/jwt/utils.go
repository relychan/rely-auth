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
func evalHasuraSessionVariables(result map[string]any) (map[string]any, error) {
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

	var defaultRoleStr, roleStr *string

	defaultRole, ok := result[authmode.XHasuraDefaultRole]
	if ok && defaultRole != nil {
		defaultRoleStr, err = goutils.DecodeNullableString(defaultRole)
		if err != nil {
			return nil, fmt.Errorf(
				"malformed %s; expected a string: %w",
				authmode.XHasuraDefaultRole,
				err,
			)
		}
	}

	desiredRole, ok := result[authmode.XHasuraRole]
	if ok && desiredRole != nil {
		roleStr, err = goutils.DecodeNullableString(desiredRole)
		if err != nil {
			return nil, fmt.Errorf("malformed %s; expected a string: %w", authmode.XHasuraRole, err)
		}
	}

	if roleStr != nil && *roleStr != "" {
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

		return result, nil
	}

	if defaultRoleStr == nil || *defaultRoleStr == "" {
		return nil, goutils.NewForbiddenError(goutils.ErrorDetail{
			Header: authmode.XHasuraDefaultRole,
			Detail: "value of x-hasura-default-role variable is empty",
		})
	}

	if !slices.Contains(allowedRoles, *defaultRoleStr) {
		return nil, goutils.NewForbiddenError(goutils.ErrorDetail{
			Header: authmode.XHasuraDefaultRole,
			Detail: fmt.Sprintf(
				"%s is not in the allowed roles %v",
				*defaultRoleStr,
				authmode.XHasuraAllowedRoles,
			),
		})
	}

	delete(result, authmode.XHasuraAllowedRoles)
	delete(result, authmode.XHasuraDefaultRole)

	result[authmode.XHasuraRole] = *defaultRoleStr

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
