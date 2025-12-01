package authmode

import (
	"testing"

	"github.com/relychan/gohttpc/authc/authscheme"
	"gotest.tools/v3/assert"
)

func TestFindAuthTokenByLocation(t *testing.T) {
	testCases := []struct {
		Name     string
		Body     AuthenticateRequestData
		Location authscheme.TokenLocation
		Expected string
		Error    string
	}{
		{
			Name: "bearer",
			Body: AuthenticateRequestData{
				Headers: map[string]string{
					"authorization": "Bearer randomsecret",
				},
			},
			Location: authscheme.TokenLocation{
				In:     authscheme.InHeader,
				Name:   "Authorization",
				Scheme: "bearer",
			},
			Expected: "randomsecret",
		},
		{
			Name: "header_without_scheme",
			Body: AuthenticateRequestData{
				Headers: map[string]string{
					"x-api-key": "mysecret",
				},
			},
			Location: authscheme.TokenLocation{
				In:   authscheme.InHeader,
				Name: "X-API-Key",
			},
			Expected: "mysecret",
		},
		{
			Name: "query_parameter",
			Body: AuthenticateRequestData{
				URL: "/api/data?token=querytoken&other=value",
			},
			Location: authscheme.TokenLocation{
				In:   authscheme.InQuery,
				Name: "token",
			},
			Expected: "querytoken",
		},
		{
			Name: "cookie",
			Body: AuthenticateRequestData{
				Headers: map[string]string{
					"cookie": "session=abc123; token=cookietoken",
				},
			},
			Location: authscheme.TokenLocation{
				In:   authscheme.InCookie,
				Name: "token",
			},
			Expected: "cookietoken",
		},
		{
			Name: "token_not_found",
			Body: AuthenticateRequestData{
				Headers: map[string]string{},
			},
			Location: authscheme.TokenLocation{
				In:   authscheme.InHeader,
				Name: "Authorization",
			},
			Error: ErrAuthTokenNotFound.Error(),
		},
		{
			Name: "wrong_scheme",
			Body: AuthenticateRequestData{
				Headers: map[string]string{
					"authorization": "Basic dXNlcjpwYXNz",
				},
			},
			Location: authscheme.TokenLocation{
				In:     authscheme.InHeader,
				Name:   "Authorization",
				Scheme: "bearer",
			},
			Expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			location, err := ValidateTokenLocation(tc.Location)
			assert.NilError(t, err)

			result, err := FindAuthTokenByLocation(&tc.Body, &location)
			if tc.Error != "" {
				assert.ErrorContains(t, err, tc.Error)

				return
			}

			assert.NilError(t, err)
			assert.Equal(t, tc.Expected, result)
		})
	}

}

func TestValidateTokenLocation(t *testing.T) {
	testCases := []struct {
		Name        string
		Location    authscheme.TokenLocation
		Expected    authscheme.TokenLocation
		ExpectError string
	}{
		{
			Name: "valid_header",
			Location: authscheme.TokenLocation{
				In:     authscheme.InHeader,
				Name:   "Authorization",
				Scheme: "Bearer",
			},
			Expected: authscheme.TokenLocation{
				In:     authscheme.InHeader,
				Name:   "authorization",
				Scheme: "bearer",
			},
		},
		{
			Name: "empty_name",
			Location: authscheme.TokenLocation{
				In: authscheme.InHeader,
			},
			ExpectError: ErrLocationNameRequired.Error(),
		},
		{
			Name: "trim_whitespace",
			Location: authscheme.TokenLocation{
				In:     authscheme.InHeader,
				Name:   "  X-API-Key  ",
				Scheme: "  Bearer  ",
			},
			Expected: authscheme.TokenLocation{
				In:     authscheme.InHeader,
				Name:   "x-api-key",
				Scheme: "bearer",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result, err := ValidateTokenLocation(tc.Location)
			if tc.ExpectError != "" {
				assert.ErrorContains(t, err, tc.ExpectError)
			} else {
				assert.NilError(t, err)
				assert.DeepEqual(t, tc.Expected, result)
			}
		})
	}
}

func TestSerializeSessionVariablesHasuraGraphQLEngine(t *testing.T) {
	testCases := []struct {
		Name        string
		Input       map[string]any
		Expected    map[string]string
		ExpectError bool
	}{
		{
			Name: "simple_string",
			Input: map[string]any{
				"x-hasura-role": "admin",
			},
			Expected: map[string]string{
				"x-hasura-role": "admin",
			},
		},
		{
			Name: "array_of_strings",
			Input: map[string]any{
				"x-hasura-allowed-roles": []any{"admin", "user"},
			},
			Expected: map[string]string{
				"x-hasura-allowed-roles": "{admin,user}",
			},
		},
		{
			Name: "mixed_types",
			Input: map[string]any{
				"x-hasura-user-id": "123",
				"x-hasura-role":    "user",
				"x-hasura-org-id":  456,
			},
			Expected: map[string]string{
				"x-hasura-user-id": "123",
				"x-hasura-role":    "user",
				"x-hasura-org-id":  "456",
			},
		},
		{
			Name: "nested_object",
			Input: map[string]any{
				"x-hasura-metadata": map[string]any{
					"foo": "bar",
				},
			},
			Expected: map[string]string{
				"x-hasura-metadata": `{"foo":"bar"}`,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result, err := SerializeSessionVariablesHasuraGraphQLEngine(tc.Input)
			if tc.ExpectError {
				assert.Assert(t, err != nil)
			} else {
				assert.NilError(t, err)
				assert.DeepEqual(t, tc.Expected, result)
			}
		})
	}
}
