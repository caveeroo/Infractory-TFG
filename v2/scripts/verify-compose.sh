#!/usr/bin/env sh
set -eu

POSTGRES_ADMIN_PASSWORD=verify-only \
INFRACTORY_DB_PASSWORD=verify-only \
PULUMI_DB_PASSWORD=verify-only \
APP_ENCRYPTION_KEY=verify-only \
PULUMI_CONFIG_PASSPHRASE=verify-only \
INFRACTORY_TOKEN_PEPPER=verify-only-not-used-at-runtime \
  docker compose config --quiet
