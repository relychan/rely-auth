.PHONY: format
format:
	gofmt -w -s .

.PHONY: test
test:
	scripts/test.sh

# Install golangci-lint tool to run lint locally
# https://golangci-lint.run/usage/install
.PHONY: lint
lint:
	golangci-lint run

.PHONY: lint-fix
lint-fix:
	golangci-lint run --fix

.PHONY: build-jsonschema
build-jsonschema:
	cd jsonschema && go run .

