#!/bin/bash

# NOTE: run this script at the root project folder:
trap "cd examples && docker compose down --remove-orphans -v" EXIT

pushd examples \
    && docker compose up -d --build auth-hook postgres engine app_mypostgres_promptql hasura \
    && popd

export DDN_SERVER_URL=http://localhost:3280/graphql
export HASURA_SERVER_URL=http://localhost:8080/v1/graphql

http_wait() {
  printf "$1:\t "
  for i in {1..60};
  do
    local code="$(curl -s -o /dev/null -m 2 -w '%{http_code}' $1)"
    if [[ $code != "200" ]]; then
      printf "."
      sleep 1
    else
      printf "\r\033[K$1:\t ${GREEN}OK${NC}\n"
      return 0
    fi
  done
  printf "\n${RED}ERROR${NC}: cannot connect to $1. Please check docker service logs.\n"
  exit 1
}

http_wait http://localhost:8080/healthz

go test -v -race -timeout 3m -coverpkg=./... -coverprofile=coverage.out ./...