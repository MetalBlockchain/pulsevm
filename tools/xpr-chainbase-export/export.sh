#!/usr/bin/env bash
# Export XPR chainbase state through XPR's Leap state-history plugin. The first
# accepted block in an empty chain-state history directory contains every live
# chainbase table as SHiP table deltas. An optional bounded post-snapshot window
# keeps nodeos running until a requested number of later blocks has arrived.

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
  --post-snapshot-blocks N Keep the source node running until at least N blocks
                           after the snapshot head are available. Requires a
                           --p2p-peer; the manifest records the observed head.

Options:
  --source-revision SHA    XPR Leap revision that produced nodeos
                          (default: d133c6413ce8ce2e96096a0513ec25b4a8dbe837)
  --xpr-core PATH          Matching XPR Leap checkout; validates the source
                          revision and deferred-sidecar plugin before export
  --timeout-seconds N      Maximum time to wait for the initial full delta (default: 300)
  --chain-state-db-size-mb N
                           Allocate N MiB for nodeos chainbase while restoring
                           the snapshot (default: nodeos default)
  --http-probe-port N      Loopback HTTP port used for bounded-window progress
                           checks (default: 18888)
  --http-probe-bind ADDR   HTTP bind address for the bounded-window probe
                           (default: 127.0.0.1)
  --wasm-runtime NAME      Leap WASM runtime (default: eos-vm; use eos-vm-oc only
                           when the source snapshot was produced with that runtime)
  --resource-monitor-space-threshold N
                           Set Leap's filesystem shutdown threshold percentage
                           (default: nodeos default; 0 disables this override)
  --deferred-sidecar PATH  Write complete deferred-transaction chainbase state
                           through the bundled source-node plugin
  --deferred-sidecar-dir PATH
                           Write a complete sidecar at startup and after each
                           accepted block, named <block-id>.json
  --help                   Show this help

The output directory contains:
  chain_state_history.log/.index  Standard XPR SHiP chain-state history
  manifest.env                     Pinned source, input and output hashes
                                  and optional bounded-window heights
  deferred-transactions.json       Optional complete deferred-transaction sidecar
  deferred-blocks/<block-id>.json  Optional per-block sidecars for delta replay
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
http_probe_port=18888
http_probe_bind=127.0.0.1
wasm_runtime="eos-vm"
resource_monitor_space_threshold=0
deferred_sidecar=""
deferred_sidecar_dir=""
xpr_core=""
post_snapshot_blocks=0
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
        --http-probe-port) http_probe_port="$2"; shift 2 ;;
        --http-probe-bind) http_probe_bind="$2"; shift 2 ;;
        --wasm-runtime) wasm_runtime="$2"; shift 2 ;;
        --resource-monitor-space-threshold) resource_monitor_space_threshold="$2"; shift 2 ;;
        --deferred-sidecar) deferred_sidecar="$2"; shift 2 ;;
        --deferred-sidecar-dir) deferred_sidecar_dir="$2"; shift 2 ;;
        --post-snapshot-blocks) post_snapshot_blocks="$2"; shift 2 ;;
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
[[ "$http_probe_port" =~ ^[1-9][0-9]{0,4}$ ]] && ((http_probe_port <= 65535)) || {
    echo "--http-probe-port must be a TCP port between 1 and 65535" >&2
    exit 2
}
[[ "$resource_monitor_space_threshold" =~ ^[0-9]+$ ]] &&
    ((resource_monitor_space_threshold == 0 ||
      (resource_monitor_space_threshold >= 6 && resource_monitor_space_threshold <= 99))) || {
    echo "--resource-monitor-space-threshold must be 0 or between 6 and 99" >&2
    exit 2
}
[[ "$post_snapshot_blocks" =~ ^[0-9]+$ ]] || {
    echo "--post-snapshot-blocks must be a non-negative integer" >&2
    exit 2
}
if ((post_snapshot_blocks > 0 && ${#peers[@]} == 0)); then
    echo "--post-snapshot-blocks requires at least one --p2p-peer" >&2
    exit 2
fi
[[ ! -e "$work_dir" ]] || { echo "work directory already exists: $work_dir" >&2; exit 2; }
if [[ -n "$deferred_sidecar" && -e "$deferred_sidecar" ]]; then
    echo "deferred sidecar path already exists: $deferred_sidecar" >&2
    exit 2
fi
if [[ -n "$deferred_sidecar_dir" && -e "$deferred_sidecar_dir" ]]; then
    echo "deferred sidecar directory already exists: $deferred_sidecar_dir" >&2
    exit 2
fi
if [[ -n "$deferred_sidecar" && -n "$deferred_sidecar_dir" ]]; then
    echo "--deferred-sidecar and --deferred-sidecar-dir are mutually exclusive" >&2
    exit 2
fi

if [[ -n "$xpr_core" || -n "$deferred_sidecar" || -n "$deferred_sidecar_dir" ]]; then
    [[ -n "$xpr_core" ]] || {
        echo "--xpr-core is required with a deferred sidecar option" >&2
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
    if [[ -n "$deferred_sidecar" || -n "$deferred_sidecar_dir" ]]; then
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
    --p2p-listen-endpoint 127.0.0.1:0
    --plugin eosio::state_history_plugin
    --state-history-dir "$history_dir"
    --chain-state-history
    --state-history-endpoint 127.0.0.1:0
)
if ((resource_monitor_space_threshold > 0)); then
    args+=(--resource-monitor-space-threshold "$resource_monitor_space_threshold")
fi
if [[ -n "$wasm_runtime" ]]; then
    args+=(--wasm-runtime "$wasm_runtime")
fi
if ((post_snapshot_blocks > 0)); then
    # The HTTP endpoint is only used as a bounded-window progress probe. Keep
    # it loopback-only and on a non-default port so an operator's nodeos RPC
    # endpoint is not disturbed.
    args+=(
        --plugin eosio::http_plugin
        --plugin eosio::chain_api_plugin
        --http-server-address "$http_probe_bind:$http_probe_port"
        --http-validate-host false
    )
fi
if ((chain_state_db_size_mb > 0)); then
    args+=(--chain-state-db-size-mb "$chain_state_db_size_mb")
fi
if [[ -n "$deferred_sidecar" ]]; then
    args+=(
        --plugin eosio::deferred_transaction_sidecar_plugin
        --deferred-transaction-sidecar-path "$deferred_sidecar"
    )
elif [[ -n "$deferred_sidecar_dir" ]]; then
    args+=(
        --plugin eosio::deferred_transaction_sidecar_plugin
        --deferred-transaction-sidecar-dir "$deferred_sidecar_dir"
    )
fi
if ((${#peers[@]})); then
    for peer in "${peers[@]}"; do
        args+=(--p2p-peer-address "$peer")
    done
fi

if ((post_snapshot_blocks > 0)); then
    XPR_NODEOS_HTTP_PORT="$http_probe_port" "$nodeos" "${args[@]}" >"$nodeos_log" 2>&1 &
else
    "$nodeos" "${args[@]}" >"$nodeos_log" 2>&1 &
fi
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
       && { [[ -z "$deferred_sidecar" ]] || [[ -s "$deferred_sidecar" ]]; } \
       && { [[ -z "$deferred_sidecar_dir" ]] || compgen -G "$deferred_sidecar_dir/*.json" >/dev/null; }; then
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
if [[ -n "$deferred_sidecar_dir" ]] && ! compgen -G "$deferred_sidecar_dir/*.json" >/dev/null; then
    echo "nodeos produced SHiP but no per-block deferred sidecars; ensure the rebuilt source plugin is enabled" >&2
    exit 1
fi

snapshot_head_block=""
target_head_block=""
observed_head_block=""
if ((post_snapshot_blocks > 0)); then
    # The first state-history record is keyed by the snapshot's accepted block
    # id. Block ids encode the height in their first four bytes, big-endian.
    snapshot_head_hex="$(od -An -tx1 -j8 -N4 "$history_log" | tr -d ' \n')"
    [[ "$snapshot_head_hex" =~ ^[[:xdigit:]]{8}$ ]] || {
        echo "could not read snapshot head block id from $history_log" >&2
        exit 1
    }
    snapshot_head_block="$((16#$snapshot_head_hex))"
    target_head_block=$((snapshot_head_block + post_snapshot_blocks))

    get_head_block() {
        curl --fail --silent --show-error \
            "http://127.0.0.1:$http_probe_port/v1/chain/get_info" \
            | sed -n 's/.*"head_block_num"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p'
    }

    for ((elapsed = 0; elapsed < timeout_seconds; elapsed++)); do
        observed_head_block="$(get_head_block || true)"
        if [[ "$observed_head_block" =~ ^[0-9]+$ ]] &&
            ((observed_head_block >= target_head_block)); then
            break
        fi
        if ! kill -0 "$nodeos_pid" 2>/dev/null; then
            echo "nodeos exited before bounded window reached; see $nodeos_log" >&2
            exit 1
        fi
        sleep 1
    done
    [[ "$observed_head_block" =~ ^[0-9]+$ ]] &&
        ((observed_head_block >= target_head_block)) || {
        echo "timed out waiting for block $target_head_block; observed ${observed_head_block:-unknown}; see $nodeos_log" >&2
        exit 1
    }
fi

# Stop the source node before hashing the history log. In bounded mode it can
# receive a few more blocks while the manifest is being written otherwise,
# leaving the recorded checksum out of sync with the final artifact.
cleanup
trap - EXIT INT TERM

sha256() {
    if command -v sha256sum >/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

sha256_directory() {
    local directory="$1"
    local files
    files="$(find "$directory" -maxdepth 1 -type f -name '*.json' -print | LC_ALL=C sort)"
    if command -v sha256sum >/dev/null; then
        if [[ -n "$files" ]]; then
            while IFS= read -r file; do
                printf '%s  %s\n' "$(sha256 "$file")" "${file#"$directory"/}"
            done <<<"$files" | sha256sum | awk '{print $1}'
        else
            printf '' | sha256sum | awk '{print $1}'
        fi
    else
        if [[ -n "$files" ]]; then
            while IFS= read -r file; do
                printf '%s  %s\n' "$(sha256 "$file")" "${file#"$directory"/}"
            done <<<"$files" | shasum -a 256 | awk '{print $1}'
        else
            printf '' | shasum -a 256 | awk '{print $1}'
        fi
    fi
}

{
    printf 'XPR_CORE_REVISION=%s\n' "$source_revision"
    printf 'INPUT_SNAPSHOT_SHA256=%s\n' "$(sha256 "$snapshot")"
    printf 'CHAIN_STATE_HISTORY_SHA256=%s\n' "$(sha256 "$history_log")"
    printf 'CHAIN_STATE_HISTORY_LOG=%s\n' "$(basename "$history_log")"
    printf 'SOURCE_SNAPSHOT=%s\n' "$snapshot"
    if ((post_snapshot_blocks > 0)); then
        printf 'SNAPSHOT_HEAD_BLOCK=%s\n' "$snapshot_head_block"
        printf 'POST_SNAPSHOT_BLOCKS=%s\n' "$post_snapshot_blocks"
        printf 'TARGET_HEAD_BLOCK=%s\n' "$target_head_block"
        printf 'OBSERVED_HEAD_BLOCK=%s\n' "$observed_head_block"
    fi
    if [[ -n "$deferred_sidecar" ]]; then
        printf 'DEFERRED_TRANSACTION_SIDECAR=%s\n' "$deferred_sidecar"
        printf 'DEFERRED_TRANSACTION_SIDECAR_SHA256=%s\n' "$(sha256 "$deferred_sidecar")"
    fi
    if [[ -n "$deferred_sidecar_dir" ]]; then
        printf 'DEFERRED_TRANSACTION_SIDECAR_DIR=%s\n' "$deferred_sidecar_dir"
        printf 'DEFERRED_TRANSACTION_SIDECAR_FILES=%s\n' "$(find "$deferred_sidecar_dir" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d ' ')"
        printf 'DEFERRED_TRANSACTION_SIDECAR_SHA256=%s\n' "$(sha256_directory "$deferred_sidecar_dir")"
    fi
} >"$work_dir/manifest.env"

echo "exported full XPR chain-state history to $work_dir"
