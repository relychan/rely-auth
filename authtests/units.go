package authtests

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/relychan/rely-auth/auth/authmode"
	"gotest.tools/v3/assert"
)

//go:embed testdata/config.yaml
var configYaml []byte

//go:embed testdata/webhook.yaml
var webhookYaml []byte

type SetupTestServerFunc func(t *testing.T, configPath string) (*httptest.Server, func())

const (
	testJWTIdToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbXMuand0Lmhhc3VyYS5pbyI6eyJ4LWhhc3VyYS1hbGxvd2VkLXJvbGVzIjpbInVzZXIiLCJhZG1pbiJdLCJ4LWhhc3VyYS1kZWZhdWx0LXJvbGUiOiJ1c2VyIiwieC1oYXN1cmEtZ3JvdXAtaWQiOjEwfSwiaXNzIjoiaHR0cHM6Ly9yZWx5Y2hhbi5jb20iLCJzdWIiOiJ1c2VyLWlkIiwiYXVkIjoiaHR0cHM6Ly9yZWx5Y2hhbi5jb20iLCJpYXQiOjE3NjA5Mzk5NTQsImV4cCI6OTc2MTAyNjM1NH0.0UuGOB-MPUCwhoMUCyHA7XN5Q05NmZ_j0Mc13oWquN4"
	testJWTKey     = "NTNv7j0TuYARvmNMmWXo6fKvM4o6nvxyz"
)

func TestHasuraAuthHookHandlers(t *testing.T, setupServer SetupTestServerFunc) {
	t.Setenv("JWT_KEY", testJWTKey)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "auth-config.yaml")

	assert.NilError(t, os.WriteFile(configPath, configYaml, 0644))

	server, close := setupServer(t, configPath)
	defer close()

	t.Run("ddn", func(t *testing.T) {
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
					URL: requestURL,
					Headers: map[string]string{
						"authorization":  "randomsecret",
						"true-client-ip": "127.0.0.1",
						"origin":         "http://localhost:1234",
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
					URL: requestURL,
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
				Name: "noAuth",
				Body: authmode.AuthenticateRequestData{
					URL: requestURL,
					Headers: map[string]string{
						"Origin": "http://localhost:8080",
					},
				},
				StatusCode: 200,
				ResponseBody: map[string]any{
					"x-hasura-role": "anonymous",
				},
			},
			{
				Name: "unauthorized",
				Body: authmode.AuthenticateRequestData{
					URL: requestURL,
					Headers: map[string]string{
						"Authorization": "test",
					},
				},
				StatusCode: 401,
			},
			{
				Name: "unauthorized_mode",
				Body: authmode.AuthenticateRequestData{
					URL: requestURL,
					Headers: map[string]string{
						"Authorization":    "test",
						"X-Rely-Auth-Mode": "jwt",
					},
				},
				StatusCode: 401,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.Name, func(t *testing.T) {
				runRequest(t, http.MethodPost, tc.Body, tc.StatusCode, tc.ResponseBody)
			})
		}
	})

	t.Run("hasura_v2", func(t *testing.T) {
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
					URL: requestURL,
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
					URL: requestURL,
					Headers: map[string]string{
						"Authorization": "Bearer " + testJWTIdToken,
					},
				},
				StatusCode: 200,
				ResponseBody: map[string]any{
					"x-hasura-role":     "user",
					"x-hasura-group-id": "10",
					"x-hasura-user-id":  "user-id",
				},
			},
			{
				Name: "noAuth",
				Body: authmode.AuthenticateRequestData{
					URL: requestURL,
					Headers: map[string]string{
						"origin": "http://localhost:1234",
					},
				},
				StatusCode: 200,
				ResponseBody: map[string]any{
					"x-hasura-role": "anonymous",
				},
			},
			{
				Name: "unauthorized",
				Body: authmode.AuthenticateRequestData{
					URL: requestURL,
					Headers: map[string]string{
						"Authorization":  "test",
						"X-Rely-Auth-ID": "test_jwt",
					},
				},
				StatusCode: 401,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.Name, func(t *testing.T) {
				runRequest(t, http.MethodPost, tc.Body, tc.StatusCode, tc.ResponseBody)
			})
		}
	})
}

func TestAuthWebhook(t *testing.T, setupServer SetupTestServerFunc) {
	webhookServer := initWebhookServer(t)
	defer webhookServer.Close()

	t.Setenv("AUTH_HOOK_URL", webhookServer.URL+"/authorize")
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "auth-webhook.yaml")

	assert.NilError(t, os.WriteFile(configPath, webhookYaml, 0644))

	server, close := setupServer(t, configPath)
	defer close()

	requestURL := server.URL + "/auth/ddn"
	testCases := []struct {
		Name         string
		Method       string
		Body         authmode.AuthenticateRequestData
		StatusCode   int
		ResponseBody map[string]any
	}{
		{
			Name:   "get",
			Method: http.MethodGet,
			Body: authmode.AuthenticateRequestData{
				URL: requestURL,
			},
			StatusCode: 200,
			ResponseBody: map[string]any{
				"x-hasura-role": "admin",
			},
		},
		{
			Name:   "post",
			Method: http.MethodPost,
			Body: authmode.AuthenticateRequestData{
				URL: requestURL,
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
			runRequest(t, tc.Method, tc.Body, tc.StatusCode, tc.ResponseBody)
		})
	}
}

func runRequest[T any](t *testing.T, method string, body authmode.AuthenticateRequestData, statusCode int, expectedBody T) {
	t.Helper()

	var resp *http.Response
	var err error

	switch method {
	case http.MethodGet:
		req, err := http.NewRequest(method, body.URL, nil)
		assert.NilError(t, err)

		for key, header := range body.Headers {
			req.Header.Set(key, header)
		}

		resp, err = http.DefaultClient.Do(req)
		assert.NilError(t, err)
	case http.MethodPost:
		bodyBytes, err := json.Marshal(body)
		assert.NilError(t, err)

		req, err := http.NewRequest(method, body.URL, bytes.NewReader(bodyBytes))
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
