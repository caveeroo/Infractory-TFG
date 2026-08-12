#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/../apps/agent"

if command -v go >/dev/null 2>&1; then
  go test ./...
  go vet ./...
else
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    --env GOCACHE=/tmp/go-build \
    --env GOMODCACHE=/tmp/go-mod \
    --volume "$PWD:/workspace" \
    --workdir /workspace \
    golang:1.25-bookworm \
    sh -ec 'go test ./... && go vet ./...'
fi
