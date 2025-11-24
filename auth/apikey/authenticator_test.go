package apikey

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/hasura/goenvconf"
	"github.com/relychan/gohttpc/authc/authscheme"
	"github.com/relychan/rely-auth/auth/authmode"
	"gotest.tools/v3/assert"
)

func TestAPIKeyAuthenticator(t *testing.T) {
	apiKey := rand.Text()
	sessionVariables := map[string]goenvconf.EnvAny{
		"foo": goenvconf.NewEnvAnyValue("bar"),
	}

	t.Setenv("API_KEY", apiKey)

	config := NewRelyAuthAPIKeyConfig(authscheme.TokenLocation{
		In:     authscheme.InHeader,
		Name:   "Authorization",
		Scheme: "bearer",
	}, goenvconf.NewEnvStringVariable("API_KEY"), sessionVariables)

	authenticator, err := NewAPIKeyAuthenticator(*config)
	assert.NilError(t, err)

	for range 10 {
		go func() {
			result, err := authenticator.Authenticate(context.Background(), authmode.AuthenticateRequestData{
				Headers: map[string]string{
					"authorization": "Bearer " + apiKey,
				},
			})
			assert.NilError(t, err)
			assert.DeepEqual(t, result.SessionVariables, map[string]any{"foo": "bar"})
			time.Sleep(time.Millisecond)
		}()
	}

	for range 10 {
		assert.NilError(t, authenticator.Reload(context.Background()))
		time.Sleep(time.Millisecond)
	}
}
