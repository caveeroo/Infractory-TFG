#!/usr/bin/env sh
set -eu

repository_root=$(git rev-parse --show-toplevel)
cd "$repository_root"

unexpected=$(git status --porcelain --untracked-files=all -- . ':(exclude)v2' || true)
if [ -n "$unexpected" ]; then
  echo "V1 or repository-root files changed:" >&2
  echo "$unexpected" >&2
  exit 1
fi

echo "Workspace boundary intact: all changes are contained in v2."
