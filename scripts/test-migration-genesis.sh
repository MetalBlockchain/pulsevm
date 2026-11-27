#!/usr/bin/env bash
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO/scripts/lib/migration-genesis.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf '{"initial_key":"base"}\n' > "$work/base.json"
export PULSEVM_SIGNING_CHAIN_ID
PULSEVM_SIGNING_CHAIN_ID="$(printf '12%.0s' {1..32})"
build_migration_genesis "$work/base.json" "$work/a.json" checkpoint schedule override
jq -e --arg id "$PULSEVM_SIGNING_CHAIN_ID" '.chain_id == $id and .initial_key == "override" and .migration_checkpoint_sha256 == "checkpoint" and .migration_schedule_sha256 == "schedule"' "$work/a.json" >/dev/null
PULSEVM_SIGNING_CHAIN_ID=''
build_migration_genesis "$work/base.json" "$work/b.json" checkpoint schedule ''
jq -e 'has("chain_id") == false and .initial_key == "base"' "$work/b.json" >/dev/null
PULSEVM_SIGNING_CHAIN_ID=invalid
if build_migration_genesis "$work/base.json" "$work/c.json" checkpoint schedule ''; then
  echo 'invalid signing ID was accepted' >&2
  exit 1
fi
printf 'migration genesis checks passed\n'
