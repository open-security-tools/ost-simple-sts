#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=scripts/action-values.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/action-values.sh"

assert_equal() {
  local expected="$1"
  local actual="$2"
  if [[ "$actual" != "$expected" ]]; then
    printf '%s\n' "expected: $expected" >&2
    printf '%s\n' "actual:   $actual" >&2
    exit 1
  fi
}

response='{"token":"synthetic-installation","expires_at":"2026-07-15T20:00:00Z","repository":"example/repo","ref":"refs/heads/main"}'
assert_equal 'synthetic-installation' "$(read_action_string token <<<"$response")"
assert_equal '2026-07-15T20:00:00Z' "$(read_action_string expires_at <<<"$response")"
assert_equal 'example/repo' "$(read_action_string repository <<<"$response")"
assert_equal 'refs/heads/main' "$(read_action_string ref <<<"$response")"

for invalid in \
  '{"token":""}' \
  '{"token":null}' \
  '{"token":123}' \
  '{"token":"synthetic\n::warning::injected"}' \
  '{"token":"synthetic\r::warning::injected"}'; do
  if read_action_string token <<<"$invalid" >/dev/null 2>&1; then
    printf '%s\n' 'accepted an invalid or multiline action value' >&2
    exit 1
  fi
done

masked=$(mask_action_value $'synthetic%token\r\n::warning::injected')
assert_equal '::add-mask::synthetic%25token%0D%0A::warning::injected' "$masked"

printf '%s\n' 'action value tests passed'
