#!/usr/bin/env bash
# One genesis recipe for both the ceremony and the nodes it authorizes.
build_migration_genesis() {
  local base="$1" output="$2" checkpoint="$3" schedule="$4" initial_key="$5"
  local signing_id="${PULSEVM_SIGNING_CHAIN_ID:-}"
  if [[ -n "$signing_id" && ! "$signing_id" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo 'error: PULSEVM_SIGNING_CHAIN_ID must be 64 hexadecimal characters' >&2
    return 1
  fi
  jq --arg checkpoint "$checkpoint" --arg schedule "$schedule" \
    --arg initial_key "$initial_key" --arg signing_id "$signing_id" \
    '. + {migration_checkpoint_sha256: $checkpoint, migration_schedule_sha256: $schedule}
     | if $initial_key == "" then . else . + {initial_key: $initial_key} end
     | if $signing_id == "" then . else . + {chain_id: $signing_id} end' \
    "$base" > "$output"
}
