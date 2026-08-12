#!/usr/bin/env sh
set -eu

v2_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
target="$v2_root/.env"
if [ -e "$target" ]; then
  echo "$target already exists; refusing to overwrite it." >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "OpenSSL is required to generate local secrets." >&2
  exit 1
fi

random_hex() { openssl rand -hex "$1"; }
random_base64() { openssl rand -base64 "$1" | tr -d '\n'; }

umask 077
{
  echo "PUBLIC_BASE_URL=http://localhost:8080"
  echo "DATABASE_URL=postgres://infractory:unused-by-compose@postgres:5432/infractory"
  echo "PULUMI_BACKEND_URL=postgres://pulumi:unused-by-compose@postgres:5432/infractory_pulumi"
  echo "POSTGRES_ADMIN_PASSWORD=$(random_hex 24)"
  echo "INFRACTORY_DB_PASSWORD=$(random_hex 24)"
  echo "PULUMI_DB_PASSWORD=$(random_hex 24)"
  echo "APP_ENCRYPTION_KEY=$(random_base64 32)"
  echo "PULUMI_CONFIG_PASSPHRASE=$(random_base64 32)"
  echo "INFRACTORY_TOKEN_PEPPER=$(random_hex 32)"
  echo "INFRASTRUCTURE_DRIVER=fake"
  echo "AWS_REGION=eu-west-1"
  echo "AWS_ALLOWED_REGIONS=eu-west-1"
  echo "LOG_LEVEL=info"
  echo "WORKER_CONCURRENCY=4"
  echo "PULUMI_CONCURRENCY=2"
  echo "PUBLIC_ADDRESS=http://:8080"
  echo "PUBLIC_BIND_ADDRESS=127.0.0.1"
  echo "PUBLIC_PORT=8080"
  echo "PUBLIC_HTTP_PORT=80"
  echo "PUBLIC_HTTPS_PORT=443"
} > "$target"

echo "Created $target with restrictive permissions."
