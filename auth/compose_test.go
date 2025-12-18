package auth

import (
	"testing"

	"github.com/relychan/rely-auth/auth/authmode"
	"gotest.tools/v3/assert"
)

func TestNewComposedAuthenticator(t *testing.T) {
	ca := NewComposedAuthenticator([]authmode.RelyAuthenticator{})
	assert.Equal(t, ca.Mode(), authmode.AuthModeComposed)
}
