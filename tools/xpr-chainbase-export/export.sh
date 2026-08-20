#!/usr/bin/env bash
# Export the complete XPR chainbase state through XPR core's state-history
# plugin. The first accepted block in an empty chain-state history directory
# contains every live chainbase table as SHiP table deltas.

set -euo pipefail

readonly pinned_core_revision="cbb24506280275f4fb51fb9d77758ff8249fa655"

usage() {
    cat <<'EOF'
Usage:
  export.sh --nodeos PATH --snapshot PATH --work-dir PATH --p2p-peer HOST:PORT [options]

Required:
  --nodeos PATH            XPR core nodeos binary built from the source revision below
  --snapshot PATH          XPR nodeos snapshot (.bin) to hydrate
  --work-dir PATH          New directory for this export; it must not exist
  --p2p-peer HOST:PORT     Peer used to receive one post-snapshot block; repeatable

Options:
  --source-revision SHA    XPR core revision that produced nodeos
                          (default: cbb24506280275f4fb51fb9d77758ff8249fa655)
  --timeout-seconds N      Maximum time to wait for the initial full delta (default: 300)
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
deferred_sidecar=""
peers=()

while (($#)); do
    case "$1" in
        --nodeos) nodeos="$2"; shift 2 ;;
        --snapshot) snapshot="$2"; shift 2 ;;
        --work-dir) work_dir="$2"; shift 2 ;;
        --p2p-peer) peers+=("$2"); shift 2 ;;
        --source-revision) source_revision="$2"; shift 2 ;;
        --timeout-seconds) timeout_seconds="$2"; shift 2 ;;
        --deferred-sidecar) deferred_sidecar="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -x "$nodeos" ]] || { echo "nodeos is not executable: $nodeos" >&2; exit 2; }
[[ -f "$snapshot" ]] || { echo "snapshot does not exist: $snapshot" >&2; exit 2; }
[[ -n "$work_dir" ]] || { echo "--work-dir is required" >&2; exit 2; }
((${#peers[@]})) || { echo "at least one --p2p-peer is required" >&2; exit 2; }
[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
    echo "--timeout-seconds must be a positive integer" >&2
    exit 2
}
[[ ! -e "$work_dir" ]] || { echo "work directory already exists: $work_dir" >&2; exit 2; }
if [[ -n "$deferred_sidecar" && -e "$deferred_sidecar" ]]; then
    echo "deferred sidecar path already exists: $deferred_sidecar" >&2
    exit 2
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
if [[ -n "$deferred_sidecar" ]]; then
    args+=(
        --plugin eosio::deferred_transaction_sidecar_plugin
        --deferred-transaction-sidecar-path "$deferred_sidecar"
    )
fi
for peer in "${peers[@]}"; do
    args+=(--p2p-peer-address "$peer")
done

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
    if [[ -s "$history_log" ]]; then
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
