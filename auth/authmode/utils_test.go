package authmode

import (
	"testing"

	"github.com/relychan/gorestly/authc/authscheme"
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
