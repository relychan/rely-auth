#!/bin/bash

# NOTE: run this script at the root project folder:
trap "cd examples/hasura && docker compose down --remove-orphans -v" EXIT

pushd examples/hasura \
    && docker compose up -d --wait --build auth-hook postgres engine app_mypostgres_promptql hasura \
    && popd

export DDN_SERVER_URL=http://localhost:3280/graphql
export HASURA_SERVER_URL=http://localhost:8080/v1/graphql

go test -v -race -timeout 3m -coverpkg=./... -coverprofile=coverage.out ./...