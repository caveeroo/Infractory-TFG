#!/usr/bin/env sh
set -eu

artifact_directory=${INFRACTORY_AGENT_ARTIFACT_DIRECTORY:-/opt/infractory/artifacts}
case "$(uname -m)" in
  x86_64) artifact_architecture=amd64 ;;
  aarch64|arm64) artifact_architecture=arm64 ;;
  *) echo "Unsupported control-plane architecture: $(uname -m)" >&2; exit 1 ;;
esac
if [ -z "${INFRACTORY_PKI_HELPER_PATH:-}" ]; then
  INFRACTORY_PKI_HELPER_PATH="$artifact_directory/infractory-pki-linux-$artifact_architecture"
  export INFRACTORY_PKI_HELPER_PATH
fi
if [ -z "${INFRACTORY_AGENT_AMD64_SHA256:-}" ] && [ -f "$artifact_directory/SHA256SUMS" ]; then
  INFRACTORY_AGENT_AMD64_SHA256=$(awk '$2 == "infractory-agent-linux-amd64" { print $1 }' "$artifact_directory/SHA256SUMS")
  export INFRACTORY_AGENT_AMD64_SHA256
fi

exec "$@"
