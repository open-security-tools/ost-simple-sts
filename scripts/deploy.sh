#!/usr/bin/env bash
#
# Build and deploy the ost-simple-sts SAM stack.
#
# Usage:
#   ./scripts/deploy.sh              # uses .env in project root
#   ENV_FILE=/path/to/.env ./scripts/deploy.sh
#
# Required .env variables:
#   STACK_NAME                  CloudFormation stack name
#   POLICY_REPOSITORY           Repository that owns the trusted broker policy
#   POLICY_REPOSITORY_ID        Immutable ID of the policy repository
#   POLICY_INSTALLATION_ID      GitHub App installation that can read the policy
#   POLICY_PATH                 JSON policy path under .github
#   POLICY_REF                  Protected policy ref (main)
#   POLICY_AUDIENCE             Expected GitHub Actions OIDC audience
#   APP_ID_PARAMETER            SSM parameter name for App ID
#   APP_PRIVATE_KEY_SECRET_NAME Secrets Manager secret name
#   JTI_TABLE_NAME              DynamoDB table name for JTI replay guard
# Optional .env variables:
#   ALARM_TOPIC_ARN             SNS topic ARN for CloudWatch alarm notifications
#
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

require_command sam

if [[ ! -f "$ENV_FILE" ]]; then
  echo "env file not found: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

require_var STACK_NAME
require_var POLICY_REPOSITORY
require_var POLICY_REPOSITORY_ID
require_var POLICY_INSTALLATION_ID
require_var POLICY_PATH
require_var POLICY_REF
require_var POLICY_AUDIENCE
require_var APP_ID_PARAMETER
require_var APP_PRIVATE_KEY_SECRET_NAME
require_var JTI_TABLE_NAME

cd "$ROOT_DIR"

BUILD_TEMPLATE_FILE=".aws-sam/build/template.yaml"

sam build --beta-features --no-use-container

sam deploy \
  --beta-features \
  --template-file "$BUILD_TEMPLATE_FILE" \
  --resolve-s3 \
  --capabilities CAPABILITY_IAM \
  --stack-name "$STACK_NAME" \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    "ParameterKey=PolicyRepository,ParameterValue=$POLICY_REPOSITORY" \
    "ParameterKey=PolicyRepositoryId,ParameterValue=$POLICY_REPOSITORY_ID" \
    "ParameterKey=PolicyInstallationId,ParameterValue=$POLICY_INSTALLATION_ID" \
    "ParameterKey=PolicyPath,ParameterValue=$POLICY_PATH" \
    "ParameterKey=PolicyRef,ParameterValue=$POLICY_REF" \
    "ParameterKey=PolicyAudience,ParameterValue=$POLICY_AUDIENCE" \
    "ParameterKey=AppPrivateKeySecretName,ParameterValue=$APP_PRIVATE_KEY_SECRET_NAME" \
    "ParameterKey=AppIdParameterName,ParameterValue=$APP_ID_PARAMETER" \
    "ParameterKey=JtiTableName,ParameterValue=$JTI_TABLE_NAME" \
    "ParameterKey=AlarmTopicArn,ParameterValue='${ALARM_TOPIC_ARN:-}'" \
  "$@"
