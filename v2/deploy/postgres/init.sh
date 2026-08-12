#!/usr/bin/env sh
set -eu

psql \
  --set ON_ERROR_STOP=1 \
  --set app_password="$INFRACTORY_DB_PASSWORD" \
  --set pulumi_password="$PULUMI_DB_PASSWORD" \
  --username postgres <<-'SQL'
  CREATE USER infractory WITH PASSWORD :'app_password';
  CREATE DATABASE infractory OWNER infractory;
  CREATE USER pulumi WITH PASSWORD :'pulumi_password';
  CREATE DATABASE infractory_pulumi OWNER pulumi;
SQL
