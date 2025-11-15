package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/relychan/rely-auth/auth/authmode"
	"gotest.tools/v3/assert"
)

func TestHasuraDDNAuthHookHandler(t *testing.T) {
	server := initTestServer(t, "./testdata/config.yaml")
	defer server.Close()

	requestURL := server.URL + "/auth/ddn"
	testCases := []struct {
		Name         string
		Body         authmode.AuthenticateRequestData
		StatusCode   int
		ResponseBody map[string]any
	}{
		{
			Name: "apikey",
			Body: authmode.AuthenticateRequestData{
				Headers: map[string]string{
					"Authorization": "randomsecret",
				},
			},
			StatusCode: 200,
			ResponseBody: map[string]any{
				"x-hasura-role":       "admin",
				"x-some-array-int":    []any{float64(1), float64(2), float64(3)},
				"x-some-array-bool":   []any{true, false},
				"x-some-array-string": []any{"foo", "bar"},
				"x-some-object": map[string]any{
					"foo": "baz",
				},
			},
		},
		{

			Name:       "noAuth",
			Body:       authmode.AuthenticateRequestData{},
			StatusCode: 200,
			ResponseBody: map[string]any{
				"x-hasura-role": "anonymous",
			},
		},
		{

			Name: "unauthorized",
			Body: authmode.AuthenticateRequestData{
				Headers: map[string]string{
					"Authorization": "test",
				},
			},
			StatusCode: 401,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			runPreRoute(t, requestURL, tc.Body, tc.StatusCode, tc.ResponseBody)
		})
	}
}

func TestHasuraV2AuthHookHandler(t *testing.T) {
	server := initTestServer(t, "./testdata/config.yaml")
	defer server.Close()

	requestURL := server.URL + "/auth/hasura"
	testCases := []struct {
		Name         string
		Body         authmode.AuthenticateRequestData
		StatusCode   int
		ResponseBody map[string]any
	}{
		{
			Name: "apikey",
			Body: authmode.AuthenticateRequestData{
				Headers: map[string]string{
					"Authorization": "randomsecret",
				},
			},
			StatusCode: 200,
			ResponseBody: map[string]any{
				"x-hasura-role":       "admin",
				"x-some-array-int":    "{1,2,3}",
				"x-some-array-bool":   "{true,false}",
				"x-some-array-string": "{foo,bar}",
				"x-some-object":       `{"foo":"baz"}`,
			},
		},
		{

			Name:       "noAuth",
			Body:       authmode.AuthenticateRequestData{},
			StatusCode: 200,
			ResponseBody: map[string]any{
				"x-hasura-role": "anonymous",
			},
		},
		{

			Name: "unauthorized",
			Body: authmode.AuthenticateRequestData{
				Headers: map[string]string{
					"Authorization": "test",
				},
			},
			StatusCode: 401,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			runPreRoute(t, requestURL, tc.Body, tc.StatusCode, tc.ResponseBody)
		})
	}
}

func runPreRoute[T any](t *testing.T, requestURL string, body authmode.AuthenticateRequestData, statusCode int, responseBody T) {
	t.Helper()

	bodyBytes, err := json.Marshal(body)
	assert.NilError(t, err)

	resp, err := http.Post(requestURL, "application/json", bytes.NewReader(bodyBytes))
	assert.NilError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode != statusCode {
		respBody, err := io.ReadAll(resp.Body)
		assert.NilError(t, err)

		t.Errorf("expected status code: %d; got: %d; response body: %s", statusCode, resp.StatusCode, string(respBody))
		t.FailNow()
	}

	assert.Equal(t, resp.StatusCode, statusCode)

	if statusCode >= 400 {
		return
	}

	var output, empty T

	err = json.NewDecoder(resp.Body).Decode(&output)
	assert.NilError(t, err)

	// ignore empty expected response.
	if reflect.DeepEqual(responseBody, empty) {
		return
	}

	assert.DeepEqual(t, responseBody, output)
}

func initTestServer(t *testing.T, configPath string) *httptest.Server {
	t.Setenv("CONFIG_PATH", configPath)

	envVars, err := GetEnvironment()
	assert.NilError(t, err)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	authManager, err := InitAuthManager(&envVars, logger)
	assert.NilError(t, err)

	router := setupRouter(&envVars, authManager, logger)

	return httptest.NewServer(router)
}
