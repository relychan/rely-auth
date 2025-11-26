package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/hasura/gotel"
	"github.com/relychan/rely-auth/auth"
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel"
	"gotest.tools/v3/assert"
)

const testJWTIdToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbXMuand0Lmhhc3VyYS5pbyI6eyJ4LWhhc3VyYS1hbGxvd2VkLXJvbGVzIjpbInVzZXIiLCJhZG1pbiJdLCJ4LWhhc3VyYS1kZWZhdWx0LXJvbGUiOiJ1c2VyIiwieC1oYXN1cmEtZ3JvdXAtaWQiOjEwfSwiaXNzIjoiaHR0cHM6Ly9yZWx5Y2hhbi5jb20iLCJzdWIiOiJ1c2VyLWlkIiwiYXVkIjoiaHR0cHM6Ly9yZWx5Y2hhbi5jb20iLCJpYXQiOjE3NjA5Mzk5NTQsImV4cCI6OTc2MTAyNjM1NH0.0UuGOB-MPUCwhoMUCyHA7XN5Q05NmZ_j0Mc13oWquN4"

func TestHasuraDDNAuthHookHandler(t *testing.T) {
	server, authManager := initTestServer(t, "./testdata/config.yaml")
	defer server.Close()
	defer authManager.Close()

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
			Name: "jwt",
			Body: authmode.AuthenticateRequestData{
				Headers: map[string]string{
					"Authorization": "Bearer " + testJWTIdToken,
				},
			},
			StatusCode: 200,
			ResponseBody: map[string]any{
				"x-hasura-role":     "user",
				"x-hasura-group-id": float64(10),
				"x-hasura-user-id":  "user-id",
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
			runRequest(t, requestURL, http.MethodPost, tc.Body, tc.StatusCode, tc.ResponseBody)
		})
	}
}

func TestHasuraV2AuthHookHandler(t *testing.T) {
	server, authManager := initTestServer(t, "./testdata/config.yaml")
	defer server.Close()
	defer authManager.Close()

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
			Name: "jwt",
			Body: authmode.AuthenticateRequestData{
				Headers: map[string]string{
					"Authorization": "Bearer " + testJWTIdToken,
				},
			},
			StatusCode: 200,
			ResponseBody: map[string]any{
				"x-hasura-allowed-roles": []any{"user", "admin"},
				"x-hasura-default-role":  "user",
				"x-hasura-group-id":      "10",
				"x-hasura-user-id":       "user-id",
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
			runRequest(t, requestURL, http.MethodPost, tc.Body, tc.StatusCode, tc.ResponseBody)
		})
	}
}

func TestAuthWebhook(t *testing.T) {
	webhookServer := initWebhookServer(t)
	defer webhookServer.Close()

	t.Setenv("AUTH_HOOK_URL", webhookServer.URL+"/authorize")

	server, authManager := initTestServer(t, "./testdata/webhook.yaml")
	defer server.Close()
	defer authManager.Close()

	requestURL := server.URL + "/auth/ddn"
	testCases := []struct {
		Name         string
		Method       string
		Body         authmode.AuthenticateRequestData
		StatusCode   int
		ResponseBody map[string]any
	}{
		{
			Name:       "get",
			Method:     http.MethodGet,
			Body:       authmode.AuthenticateRequestData{},
			StatusCode: 200,
			ResponseBody: map[string]any{
				"x-hasura-role": "admin",
			},
		},
		{
			Name:   "post",
			Method: http.MethodPost,
			Body: authmode.AuthenticateRequestData{
				Headers: map[string]string{
					"Authorization": "Bearer posttoken",
					"x-test-header": "test",
				},
			},
			StatusCode: 200,
			ResponseBody: map[string]any{
				"x-hasura-role": "user",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			runRequest(t, requestURL, tc.Method, tc.Body, tc.StatusCode, tc.ResponseBody)
		})
	}
}

func runRequest[T any](t *testing.T, requestURL string, method string, body authmode.AuthenticateRequestData, statusCode int, expectedBody T) {
	t.Helper()

	var resp *http.Response
	var err error

	switch method {
	case http.MethodGet:
		req, err := http.NewRequest(method, requestURL, nil)
		assert.NilError(t, err)

		for key, header := range body.Headers {
			req.Header.Set(key, header)
		}

		resp, err = http.DefaultClient.Do(req)
		assert.NilError(t, err)
	case http.MethodPost:
		bodyBytes, err := json.Marshal(body)
		assert.NilError(t, err)

		req, err := http.NewRequest(method, requestURL, bytes.NewReader(bodyBytes))
		assert.NilError(t, err)

		for key, header := range body.Headers {
			req.Header.Set(key, header)
		}

		req.Header.Set("content-type", "application/json")

		resp, err = http.DefaultClient.Do(req)
		assert.NilError(t, err)
	}

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
	if reflect.DeepEqual(expectedBody, empty) {
		return
	}

	assert.DeepEqual(t, expectedBody, output)
}

func initTestServer(t *testing.T, configPath string) (*httptest.Server, *auth.RelyAuthManager) {
	t.Setenv("CONFIG_PATH", configPath)
	t.Setenv("JWT_KEY", "NTNv7j0TuYARvmNMmWXo6fKvM4o6nvxyz")

	envVars, err := GetEnvironment()
	assert.NilError(t, err)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	exporters := &gotel.OTelExporters{
		Tracer: gotel.NewTracer("test"),
		Meter:  otel.Meter("test"),
		Logger: logger,
		Shutdown: func(_ context.Context) error {
			return nil
		},
	}

	authManager, err := InitAuthManager(&envVars, exporters)
	assert.NilError(t, err)

	router := setupRouter(&envVars, authManager, exporters)

	return httptest.NewServer(router), authManager
}

func initWebhookServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer bearertoken" {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		_, _ = w.Write([]byte(`{"x-hasura-role":"admin"}`))
	})

	mux.HandleFunc("POST /authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer posttoken" {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		assert.Equal(t, r.Header.Get("x-test-header"), "")

		data, err := io.ReadAll(r.Body)
		assert.NilError(t, err)
		assert.Equal(t, `{"x-hasura-role":"user"}
`, string(data))
		_, _ = w.Write(data)
	})

	return httptest.NewServer(mux)
}
