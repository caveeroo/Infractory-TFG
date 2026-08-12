#!/usr/bin/env sh
set -eu

v2_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
output_directory="$v2_root/dist/agent"
agent_version=${AGENT_VERSION:-0.1.0}
mkdir -p "$output_directory"

build_agent() {
  for architecture in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" \
      go build -trimpath -ldflags="-s -w -X main.version=$agent_version" \
      -o "$output_directory/infractory-agent-linux-$architecture" \
      ./cmd/infractory-agent
    CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" \
      go build -trimpath -ldflags='-s -w' \
      -o "$output_directory/infractory-pki-linux-$architecture" \
      ./cmd/infractory-pki
  done
  cd "$output_directory"
  sha256sum infractory-* > SHA256SUMS
}

if command -v go >/dev/null 2>&1; then
  cd "$v2_root/apps/agent"
  build_agent
else
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    --env GOCACHE=/tmp/go-build \
    --env GOMODCACHE=/tmp/go-mod \
    --env AGENT_VERSION="$agent_version" \
    --volume "$v2_root:/workspace" \
    --workdir /workspace/apps/agent \
    golang:1.25-bookworm \
    sh -ec '
      mkdir -p /workspace/dist/agent
      for architecture in amd64 arm64; do
        CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" go build -trimpath -ldflags="-s -w -X main.version=$AGENT_VERSION" -o "/workspace/dist/agent/infractory-agent-linux-$architecture" ./cmd/infractory-agent
        CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" go build -trimpath -ldflags="-s -w" -o "/workspace/dist/agent/infractory-pki-linux-$architecture" ./cmd/infractory-pki
      done
      cd /workspace/dist/agent
      sha256sum infractory-* > SHA256SUMS
    '
fi

echo "Agent artifacts written to $output_directory"
