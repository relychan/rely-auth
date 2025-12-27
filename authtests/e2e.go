package authtests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/relychan/rely-auth/auth/authmode"
	"gotest.tools/v3/assert"
)

func TestHasuraDDNGraphQLAuth(t *testing.T) {
	// graphqlURL := "http://localhost:3280/graphql"
	graphqlURL := os.Getenv("DDN_SERVER_URL")
	if graphqlURL == "" {
		return
	}

	t.Run("apiKey", func(t *testing.T) {
		requestBody := authmode.AuthenticateRequestData{
			URL: graphqlURL,
			Headers: map[string]string{
				"Authorization": "randomsecret",
			},
			Request: []byte(`{
  "query": "query MyQuery {\n  public_artist_by_artist_id(artist_id: 1) {\n    artist_id\n    name\n  }\n}",
  "variables": {},
  "operationName": "MyQuery"
}`),
		}

		responseBody := map[string]any{
			"data": map[string]any{
				"public_artist_by_artist_id": map[string]any{
					"artist_id": float64(1),
					"name":      "AC/DC",
				},
			},
		}

		runGraphQLRequest(t, requestBody, responseBody)
	})

	t.Run("jwt", func(t *testing.T) {
		requestBody := authmode.AuthenticateRequestData{
			URL: graphqlURL,
			Headers: map[string]string{
				"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbXMuand0Lmhhc3VyYS5pbyI6eyJ4LWhhc3VyYS1hbGxvd2VkLXJvbGVzIjpbInVzZXIiLCJhZG1pbiJdLCJ4LWhhc3VyYS1kZWZhdWx0LXJvbGUiOiJ1c2VyIiwieC1oYXN1cmEtZ3JvdXAtaWQiOjEwfSwiaXNzIjoiaHR0cHM6Ly9yZWx5Y2hhbi5jb20iLCJzdWIiOiJ1c2VyLWlkIiwiYXVkIjoiaHR0cHM6Ly9yZWx5Y2hhbi5jb20iLCJpYXQiOjE3NjA5Mzk5NTQsImV4cCI6OTc2MTAyNjM1NH0.0UuGOB-MPUCwhoMUCyHA7XN5Q05NmZ_j0Mc13oWquN4",
				"x-hasura-role": "admin",
			},
			Request: []byte(`{
  "query": "query MyQuery {\n  public_artist_by_artist_id(artist_id: 2) {\n    artist_id\n    name\n  }\n}",
  "variables": {},
  "operationName": "MyQuery"
}`),
		}

		responseBody := map[string]any{
			"data": map[string]any{
				"public_artist_by_artist_id": map[string]any{
					"artist_id": float64(2),
					"name":      "Accept",
				},
			},
		}

		runGraphQLRequest(t, requestBody, responseBody)
	})
}

func TestHasuraV2GraphQLAuth(t *testing.T) {
	// graphqlURL := "http://localhost:8080/v1/graphql"
	graphqlURL := os.Getenv("HASURA_SERVER_URL")
	if graphqlURL == "" {
		return
	}

	t.Run("apiKey", func(t *testing.T) {
		requestBody := authmode.AuthenticateRequestData{
			URL: graphqlURL,
			Headers: map[string]string{
				"Authorization": "randomsecret",
			},
			Request: []byte(`{
  "query": "query MyQuery {\n  Artist_by_pk(ArtistId: 1) {\n    ArtistId\n    Name\n  }\n}\n",
  "operationName": "MyQuery"
}`),
		}

		responseBody := map[string]any{
			"data": map[string]any{
				"Artist_by_pk": map[string]any{
					"ArtistId": float64(1),
					"Name":     "AC/DC",
				},
			},
		}

		runGraphQLRequest(t, requestBody, responseBody)
	})

	t.Run("jwt", func(t *testing.T) {
		requestBody := authmode.AuthenticateRequestData{
			URL: graphqlURL,
			Headers: map[string]string{
				"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbXMuand0Lmhhc3VyYS5pbyI6eyJ4LWhhc3VyYS1hbGxvd2VkLXJvbGVzIjpbInVzZXIiLCJhZG1pbiJdLCJ4LWhhc3VyYS1kZWZhdWx0LXJvbGUiOiJ1c2VyIiwieC1oYXN1cmEtZ3JvdXAtaWQiOjEwfSwiaXNzIjoiaHR0cHM6Ly9yZWx5Y2hhbi5jb20iLCJzdWIiOiJ1c2VyLWlkIiwiYXVkIjoiaHR0cHM6Ly9yZWx5Y2hhbi5jb20iLCJpYXQiOjE3NjA5Mzk5NTQsImV4cCI6OTc2MTAyNjM1NH0.0UuGOB-MPUCwhoMUCyHA7XN5Q05NmZ_j0Mc13oWquN4",
				"x-hasura-role": "admin",
			},
			Request: []byte(`{
  "query": "query MyQuery {\n  Artist_by_pk(ArtistId: 2) {\n    ArtistId\n    Name\n  }\n}\n",
  "operationName": "MyQuery"
}`),
		}

		responseBody := map[string]any{
			"data": map[string]any{
				"Artist_by_pk": map[string]any{
					"ArtistId": float64(2),
					"Name":     "Accept",
				},
			},
		}

		runGraphQLRequest(t, requestBody, responseBody)
	})
}

func runGraphQLRequest[T any](t *testing.T, body authmode.AuthenticateRequestData, expectedBody T) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, body.URL, bytes.NewReader(body.Request))
	assert.NilError(t, err)

	for key, header := range body.Headers {
		req.Header.Set(key, header)
	}

	req.Header.Set("content-type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.NilError(t, err)

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		assert.NilError(t, err)

		t.Errorf("expected status code: %d; got: %d; response body: %s", http.StatusOK, resp.StatusCode, string(respBody))
		t.FailNow()
	}

	var output T

	err = json.NewDecoder(resp.Body).Decode(&output)
	assert.NilError(t, err)
	assert.DeepEqual(t, expectedBody, output)
}
