#!/usr/bin/env bash
set -euo pipefail

release_commit="$(git rev-parse --verify --end-of-options "${1:-HEAD}^{commit}")"
if ! git merge-base --is-ancestor "$release_commit" refs/remotes/origin/main; then
  echo 'Release commit must be reachable from origin/main' >&2
  exit 1
fi
