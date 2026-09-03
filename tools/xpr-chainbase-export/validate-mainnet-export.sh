#!/usr/bin/env bash
# Validate an XPR nodeos export before it is allowed into the migration path.
# This checks artifact hashes, the full-state SHiP record, all 19 tables, and
# the source-side code/deferred sidecar fields omitted by SHiP.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  validate-mainnet-export.sh --export-dir PATH --checkpoint PATH --arena-dir PATH
      [--source-chain-id HEX] [--snapshot PATH]

The export directory must contain manifest.env and state-history/chain_state_history.log.
If --source-chain-id is omitted, it is read from deferred-transactions.json.
The command writes 19-table-comparison.json and code-object-audit.txt beside the export.
EOF
}

export_dir=""
checkpoint=""
arena_dir=""
source_chain_id=""
snapshot=""
while (($#)); do
    case "$1" in
        --export-dir) export_dir="$2"; shift 2 ;;
        --checkpoint) checkpoint="$2"; shift 2 ;;
        --arena-dir) arena_dir="$2"; shift 2 ;;
        --source-chain-id) source_chain_id="$2"; shift 2 ;;
        --snapshot) snapshot="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done
[[ -d "$export_dir" && -f "$export_dir/manifest.env" ]] || { echo "invalid export directory: $export_dir" >&2; exit 2; }
[[ -f "$checkpoint" ]] || { echo "checkpoint does not exist: $checkpoint" >&2; exit 2; }
[[ -n "$arena_dir" ]] || { echo "--arena-dir is required" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }

history_log="$export_dir/state-history/chain_state_history.log"
sidecar="$export_dir/deferred-transactions.json"
[[ -s "$history_log" ]] || { echo "missing full state-history log: $history_log" >&2; exit 1; }
[[ -s "$sidecar" ]] || { echo "validated Mainnet export requires deferred-transactions.json" >&2; exit 1; }

manifest_value() { awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$export_dir/manifest.env"; }
sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

expected_history="$(manifest_value CHAIN_STATE_HISTORY_SHA256)"
actual_history="$(sha256_file "$history_log")"
[[ "$expected_history" == "$actual_history" ]] || { echo "history SHA-256 mismatch" >&2; exit 1; }
manifest_history_name="$(manifest_value CHAIN_STATE_HISTORY_LOG)"
[[ -z "$manifest_history_name" || "$manifest_history_name" == "$(basename "$history_log")" ]] || {
    echo "manifest names a different state-history log" >&2
    exit 1
}
if [[ -n "$snapshot" ]]; then
    [[ -f "$snapshot" ]] || { echo "snapshot does not exist: $snapshot" >&2; exit 2; }
    expected_snapshot="$(manifest_value INPUT_SNAPSHOT_SHA256)"
    actual_snapshot="$(sha256_file "$snapshot")"
    [[ -n "$expected_snapshot" && "$expected_snapshot" == "$actual_snapshot" ]] || {
        echo "input snapshot SHA-256 mismatch" >&2
        exit 1
    }
fi
expected_sidecar="$(manifest_value DEFERRED_TRANSACTION_SIDECAR_SHA256)"
if [[ -n "$expected_sidecar" ]]; then
    actual_sidecar="$(sha256_file "$sidecar")"
    [[ "$expected_sidecar" == "$actual_sidecar" ]] || { echo "sidecar SHA-256 mismatch" >&2; exit 1; }
fi

if [[ -z "$source_chain_id" ]]; then
    source_chain_id="$(jq -er '.source_chain_id | select(type == "string")' "$sidecar")"
fi
[[ "$source_chain_id" =~ ^[[:xdigit:]]{64}$ ]] || { echo "source chain id must be 64 hexadecimal characters" >&2; exit 2; }
sidecar_chain_id="$(jq -er '.source_chain_id' "$sidecar")"
[[ "$sidecar_chain_id" == "$source_chain_id" ]] || {
    echo "source chain id disagrees with deferred sidecar" >&2
    exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
(cd "$repo_root" && cargo run --quiet --release --locked -p pulsevm_database --example xpr_history_window_check -- \
    "$history_log" 0
)
(cd "$repo_root" && cargo run --quiet --release --locked -p pulsevm_database --example xpr_19_table_compare -- \
    "$history_log" "$checkpoint" "$arena_dir" "$source_chain_id" \
    "$export_dir/19-table-comparison.json"
)
(cd "$repo_root" && cargo run --quiet --release --locked -p pulsevm_database --example xpr_code_object_audit -- \
    "$history_log" "$sidecar" >"$export_dir/code-object-audit.txt"
)

printf 'validated Mainnet export\n'
printf 'source_block_id=%s\n' "$(jq -er '.source_block_id' "$export_dir/19-table-comparison.json")"
printf 'source_chain_id=%s\n' "$source_chain_id"
printf 'history_sha256=%s\n' "$actual_history"
printf 'comparison=%s\n' "$export_dir/19-table-comparison.json"
printf 'code_audit=%s\n' "$export_dir/code-object-audit.txt"
