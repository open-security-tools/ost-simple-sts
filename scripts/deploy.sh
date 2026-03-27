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

require_command jq
require_command sam

if [[ ! -f "$ENV_FILE" ]]; then
  echo "env file not found: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

POLICY_FILE="${POLICY_FILE:-$ROOT_DIR/policy.json}"
APP_ID_PARAMETER="${APP_ID_PARAMETER:-/ost/app-id}"
APP_PRIVATE_KEY_SECRET_NAME="${APP_PRIVATE_KEY_SECRET_NAME:-}"
JTI_TABLE_NAME="${JTI_TABLE_NAME:-ost-jti-replay}"
STACK_NAME="${STACK_NAME:-ost-simple-sts}"

require_var POLICY_FILE
require_var APP_PRIVATE_KEY_SECRET_NAME

if [[ ! -f "$POLICY_FILE" ]]; then
  echo "policy file not found: $POLICY_FILE" >&2
  exit 1
fi

cd "$ROOT_DIR"

sam_args=(
  deploy
  --beta-features
  --stack-name "$STACK_NAME"
  --parameter-overrides
  "PolicyJson=$(jq -c . "$POLICY_FILE")"
  "AppPrivateKeySecretName=$APP_PRIVATE_KEY_SECRET_NAME"
  "AppIdParameterName=$APP_ID_PARAMETER"
  "JtiTableName=$JTI_TABLE_NAME"
)

sam "${sam_args[@]}" "$@"
