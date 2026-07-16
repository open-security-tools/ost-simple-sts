#!/usr/bin/env bash

read_action_string() {
  local field="$1"
  jq --exit-status --raw-output --arg field "$field" '
    .[$field] | select(
      type == "string"
      and length > 0
      and (contains("\r") | not)
      and (contains("\n") | not)
    )
  '
}

mask_action_value() {
  local value="$1"
  value="${value//\%/%25}"
  value="${value//$'\r'/%0D}"
  value="${value//$'\n'/%0A}"
  printf '%s\n' "::add-mask::$value"
}
