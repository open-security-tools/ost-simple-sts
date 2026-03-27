#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "$name is required" >&2
    exit 1
  fi
}

resolve_private_key_to_file() {
  local destination="$1"

  if [[ -n "${APP_PRIVATE_KEY_FILE:-}" ]]; then
    if [[ ! -f "$APP_PRIVATE_KEY_FILE" ]]; then
      echo "private key file not found: $APP_PRIVATE_KEY_FILE" >&2
      exit 1
    fi
    cp "$APP_PRIVATE_KEY_FILE" "$destination"
    return
  fi

  if [[ -n "${APP_PRIVATE_KEY:-}" ]]; then
    printf '%b' "$APP_PRIVATE_KEY" >"$destination"
    return
  fi

  echo "either APP_PRIVATE_KEY_FILE or APP_PRIVATE_KEY is required" >&2
  exit 1
}

upsert_ssm_parameter() {
  local name="$1"
  local value="$2"

  aws ssm put-parameter \
    --name "$name" \
    --type SecureString \
    --overwrite \
    --value "$value" \
    >/dev/null
}

upsert_secret_from_file() {
  local secret_name="$1"
  local file_path="$2"

  if aws secretsmanager describe-secret --secret-id "$secret_name" >/dev/null 2>&1; then
    aws secretsmanager put-secret-value \
      --secret-id "$secret_name" \
      --secret-string "file://$file_path" \
      >/dev/null
  else
    aws secretsmanager create-secret \
      --name "$secret_name" \
      --secret-string "file://$file_path" \
      >/dev/null
  fi
}

require_command aws

if [[ ! -f "$ENV_FILE" ]]; then
  echo "env file not found: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

APP_ID_PARAMETER="${APP_ID_PARAMETER:-/ost/app-id}"
APP_PRIVATE_KEY_SECRET_NAME="${APP_PRIVATE_KEY_SECRET_NAME:-}"

require_var APP_ID
require_var APP_ID_PARAMETER
require_var APP_PRIVATE_KEY_SECRET_NAME

private_key_file="$(mktemp)"
trap 'rm -f "$private_key_file"' EXIT
resolve_private_key_to_file "$private_key_file"

upsert_ssm_parameter "$APP_ID_PARAMETER" "$APP_ID"
upsert_secret_from_file "$APP_PRIVATE_KEY_SECRET_NAME" "$private_key_file"

echo "synced APP_ID parameter and private key secret"
