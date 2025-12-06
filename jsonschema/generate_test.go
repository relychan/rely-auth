package main

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestGenerate(t *testing.T) {
	assert.NilError(t, jsonSchemaConfiguration())
}
