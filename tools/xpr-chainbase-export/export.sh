#!/usr/bin/env bash
# Export the complete XPR chainbase state through XPR's Leap state-history
# plugin. The first accepted block in an empty chain-state history directory
# contains every live chainbase table as SHiP table deltas.

set -euo pipefail

readonly pinned_core_revision="d133c6413ce8ce2e96096a0513ec25b4a8dbe837"

usage() {
    cat <<'EOF'
Usage:
  export.sh --nodeos PATH --snapshot PATH --work-dir PATH [options]

Required:
  --nodeos PATH            XPR Leap nodeos binary built from the source revision below
  --snapshot PATH          XPR nodeos snapshot (.bin) to hydrate
  --work-dir PATH          New directory for this export; it must not exist
  --p2p-peer HOST:PORT     Optional source-network peer; repeatable. Omit for
                           a snapshot-only export with no post-snapshot blocks.

Options:
  --source-revision SHA    XPR Leap revision that produced nodeos
                          (default: d133c6413ce8ce2e96096a0513ec25b4a8dbe837)
  --xpr-core PATH          Matching XPR Leap checkout; validates the source
                          revision and deferred-sidecar plugin before export
  --timeout-seconds N      Maximum time to wait for the initial full delta (default: 300)
  --chain-state-db-size-mb N
                           Allocate N MiB for nodeos chainbase while restoring
                           the snapshot (default: nodeos default)
  --deferred-sidecar PATH  Write complete deferred-transaction chainbase state
                           through the bundled source-node plugin
  --help                   Show this help

The output directory contains:
  chain_state_history.log/.index  Standard XPR SHiP chain-state history
  manifest.env                     Pinned source, input and output hashes
  deferred-transactions.json       Optional complete deferred-transaction sidecar
  nodeos.log                       Source-node diagnostic log

The importer consumes the first state-history block as a full Arena hydration
input. The script never modifies the supplied snapshot and refuses to reuse an
existing output directory.
EOF
}

nodeos=""
snapshot=""
work_dir=""
source_revision="$pinned_core_revision"
timeout_seconds=300
chain_state_db_size_mb=0
deferred_sidecar=""
xpr_core=""
peers=()

while (($#)); do
    case "$1" in
        --nodeos) nodeos="$2"; shift 2 ;;
        --snapshot) snapshot="$2"; shift 2 ;;
        --work-dir) work_dir="$2"; shift 2 ;;
        --p2p-peer) peers+=("$2"); shift 2 ;;
        --source-revision) source_revision="$2"; shift 2 ;;
        --xpr-core) xpr_core="$2"; shift 2 ;;
        --timeout-seconds) timeout_seconds="$2"; shift 2 ;;
        --chain-state-db-size-mb) chain_state_db_size_mb="$2"; shift 2 ;;
        --deferred-sidecar) deferred_sidecar="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -x "$nodeos" ]] || { echo "nodeos is not executable: $nodeos" >&2; exit 2; }
[[ -f "$snapshot" ]] || { echo "snapshot does not exist: $snapshot" >&2; exit 2; }
[[ -n "$work_dir" ]] || { echo "--work-dir is required" >&2; exit 2; }
[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
    echo "--timeout-seconds must be a positive integer" >&2
    exit 2
}
[[ "$chain_state_db_size_mb" =~ ^[0-9]+$ ]] || {
    echo "--chain-state-db-size-mb must be a non-negative integer" >&2
    exit 2
}
[[ ! -e "$work_dir" ]] || { echo "work directory already exists: $work_dir" >&2; exit 2; }
if [[ -n "$deferred_sidecar" && -e "$deferred_sidecar" ]]; then
    echo "deferred sidecar path already exists: $deferred_sidecar" >&2
    exit 2
fi

if [[ -n "$xpr_core" || -n "$deferred_sidecar" ]]; then
    [[ -n "$xpr_core" ]] || {
        echo "--xpr-core is required with --deferred-sidecar" >&2
        exit 2
    }
    preflight_args=(
        --nodeos "$nodeos"
        --snapshot "$snapshot"
        --xpr-core "$xpr_core"
        --source-revision "$source_revision"
    )
    if ((${#peers[@]})); then
        for peer in "${peers[@]}"; do
            preflight_args+=(--p2p-peer "$peer")
        done
    fi
    if [[ -n "$deferred_sidecar" ]]; then
        preflight_args+=(--require-sidecar-plugin)
    fi
    "$(dirname "${BASH_SOURCE[0]}")/preflight.sh" "${preflight_args[@]}"
fi

mkdir -p "$work_dir"/{data,config,state-history}
history_dir="$work_dir/state-history"
history_log="$history_dir/chain_state_history.log"
nodeos_log="$work_dir/nodeos.log"

args=(
    --data-dir "$work_dir/data"
    --config-dir "$work_dir/config"
    --snapshot "$snapshot"
    --disable-replay-opts
    --plugin eosio::chain_plugin
    --plugin eosio::net_plugin
    --plugin eosio::state_history_plugin
    --state-history-dir "$history_dir"
    --chain-state-history
    --state-history-endpoint 127.0.0.1:0
)
if ((chain_state_db_size_mb > 0)); then
    args+=(--chain-state-db-size-mb "$chain_state_db_size_mb")
fi
if [[ -n "$deferred_sidecar" ]]; then
    args+=(
        --plugin eosio::deferred_transaction_sidecar_plugin
        --deferred-transaction-sidecar-path "$deferred_sidecar"
    )
fi
if ((${#peers[@]})); then
    for peer in "${peers[@]}"; do
        args+=(--p2p-peer-address "$peer")
    done
fi

"$nodeos" "${args[@]}" >"$nodeos_log" 2>&1 &
nodeos_pid=$!

cleanup() {
    if kill -0 "$nodeos_pid" 2>/dev/null; then
        kill -INT "$nodeos_pid" 2>/dev/null || true
        wait "$nodeos_pid" || true
    fi
}
trap cleanup EXIT INT TERM

for ((elapsed = 0; elapsed < timeout_seconds; elapsed++)); do
    # state_history_plugin emits this completion log only after its initial
    # snapshot record is fully flushed. Wait for it and the optional sidecar,
    # rather than treating the first bytes of a live log as a complete export.
    if rg -q 'Done storing initial state on startup' "$nodeos_log" \
       && [[ -s "$history_log" ]] \
       && { [[ -z "$deferred_sidecar" ]] || [[ -s "$deferred_sidecar" ]]; }; then
        break
    fi
    if ! kill -0 "$nodeos_pid" 2>/dev/null; then
        echo "nodeos exited before producing chain state; see $nodeos_log" >&2
        exit 1
    fi
    sleep 1
done

[[ -s "$history_log" ]] || {
    echo "timed out waiting for full chain-state delta; see $nodeos_log" >&2
    exit 1
}
rg -q 'Done storing initial state on startup' "$nodeos_log" || {
    echo "timed out waiting for complete chain-state delta; see $nodeos_log" >&2
    exit 1
}
if [[ -n "$deferred_sidecar" && ! -s "$deferred_sidecar" ]]; then
    echo "nodeos produced SHiP but no deferred-transaction sidecar; ensure it was rebuilt with tools/xpr-chainbase-export/deferred-sidecar-plugin" >&2
    exit 1
fi

sha256() {
    if command -v sha256sum >/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

{
    printf 'XPR_CORE_REVISION=%s\n' "$source_revision"
    printf 'INPUT_SNAPSHOT_SHA256=%s\n' "$(sha256 "$snapshot")"
    printf 'CHAIN_STATE_HISTORY_SHA256=%s\n' "$(sha256 "$history_log")"
    printf 'CHAIN_STATE_HISTORY_LOG=%s\n' "$(basename "$history_log")"
    printf 'SOURCE_SNAPSHOT=%s\n' "$snapshot"
    if [[ -n "$deferred_sidecar" ]]; then
        printf 'DEFERRED_TRANSACTION_SIDECAR=%s\n' "$deferred_sidecar"
        printf 'DEFERRED_TRANSACTION_SIDECAR_SHA256=%s\n' "$(sha256 "$deferred_sidecar")"
    fi
} >"$work_dir/manifest.env"

echo "exported full XPR chain-state history to $work_dir"
