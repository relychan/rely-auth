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

package jwt

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
)

func TestJWTClaimsFormat_Validate(t *testing.T) {
	testCases := []struct {
		Name        string
		Format      JWTClaimsFormat
		ExpectError bool
	}{
		{
			Name:        "valid_json",
			Format:      JWTClaimsFormatJSON,
			ExpectError: false,
		},
		{
			Name:        "valid_stringified_json",
			Format:      JWTClaimsFormatStringifiedJSON,
			ExpectError: false,
		},
		{
			Name:        "invalid_format",
			Format:      "Invalid",
			ExpectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			err := tc.Format.Validate()
			if tc.ExpectError {
				assert.ErrorContains(t, err, ErrInvalidJWTClaimsFormat.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseJWTClaimsFormat(t *testing.T) {
	testCases := []struct {
		Name        string
		Value       string
		Expected    JWTClaimsFormat
		ExpectError bool
	}{
		{
			Name:        "valid_json",
			Value:       "Json",
			Expected:    JWTClaimsFormatJSON,
			ExpectError: false,
		},
		{
			Name:        "valid_stringified_json",
			Value:       "StringifiedJson",
			Expected:    JWTClaimsFormatStringifiedJSON,
			ExpectError: false,
		},
		{
			Name:        "invalid_format",
			Value:       "Invalid",
			ExpectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result, err := ParseJWTClaimsFormat(tc.Value)
			if tc.ExpectError {
				assert.ErrorContains(t, err, ErrInvalidJWTClaimsFormat.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.Expected, result)
			}
		})
	}
}

func TestGetSupportedJWTClaimsFormats(t *testing.T) {
	formats := GetSupportedJWTClaimsFormats()
	assert.True(t, len(formats) == 2)
	assert.True(t, formats[0] == JWTClaimsFormatJSON)
	assert.True(t, formats[1] == JWTClaimsFormatStringifiedJSON)
}

func TestParseSignatureAlgorithm(t *testing.T) {
	testCases := []struct {
		Name        string
		Value       string
		Expected    jose.SignatureAlgorithm
		ExpectError bool
	}{
		{
			Name:        "valid_hs256",
			Value:       "HS256",
			Expected:    jose.HS256,
			ExpectError: false,
		},
		{
			Name:        "valid_rs256",
			Value:       "RS256",
			Expected:    jose.RS256,
			ExpectError: false,
		},
		{
			Name:        "valid_es256",
			Value:       "ES256",
			Expected:    jose.ES256,
			ExpectError: false,
		},
		{
			Name:        "valid_ps256",
			Value:       "PS256",
			Expected:    jose.PS256,
			ExpectError: false,
		},
		{
			Name:        "valid_eddsa",
			Value:       "EdDSA",
			Expected:    jose.EdDSA,
			ExpectError: false,
		},
		{
			Name:        "invalid_algorithm",
			Value:       "INVALID",
			ExpectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result, err := ParseSignatureAlgorithm(tc.Value)
			if tc.ExpectError {
				assert.ErrorContains(t, err, ErrInvalidSignatureAlgorithm.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.Expected, result)
			}
		})
	}
}

func TestGetSupportedSignatureAlgorithms(t *testing.T) {
	algorithms := GetSupportedSignatureAlgorithms()
	assert.True(t, len(algorithms) == 13)

	// Check that all expected algorithms are present
	expectedAlgorithms := []jose.SignatureAlgorithm{
		jose.ES256, jose.ES384, jose.ES512,
		jose.EdDSA,
		jose.HS256, jose.HS384, jose.HS512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.RS256, jose.RS384, jose.RS512,
	}

	for _, expected := range expectedAlgorithms {
		found := false
		for _, alg := range algorithms {
			if alg == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected algorithm %s not found", expected)
	}
}
