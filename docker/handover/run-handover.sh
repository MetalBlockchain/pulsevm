#!/usr/bin/env bash
# Rehearse the shadow-then-promote handover: Leap produces, PulseVM shadows,
# the producer halts at TERMINAL_HEIGHT, and a five-node PulseVM network
# boots from the checkpointed shadow state and continues at H+1.
#
# Phase 2 note: promotion currently re-identifies the chain (the migration
# genesis commits to the checkpoint hash). Same-ID in-process promotion is
# future work; this rehearsal validates follow, halt, checkpoint, boot,
# parent linkage, and liveness.
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
readonly TERMINAL_HEIGHT="${TERMINAL_HEIGHT:-1200}"
readonly WORK_DIR="${HANDOVER_WORK_DIR:-/tmp/pulsevm-handover}"
readonly LEAP_API="http://127.0.0.1:${LEAP_HTTP_PORT:-8888}"
readonly SHADOW_RPC="http://127.0.0.1:${SHADOW_RPC_PORT:-9660}"
readonly XPR_CORE_DIR="${XPR_CORE_DIR:-/src/antelope-leap}"
readonly NETWORK_RUNNER="${METAL_NETWORK_RUNNER_PATH:-$REPO_ROOT/../metal-network-runner/bin/metal-network-runner}"
readonly RUNNER_ENDPOINT="${METAL_NETWORK_RUNNER_ENDPOINT:-127.0.0.1:8081}"

# Set early so every compose invocation (including stop) interpolates.
export PULSEVM_REPLAY_BIN="${PULSEVM_REPLAY_BIN:-$REPO_ROOT/target/release/examples/xpr_blocklog_replay}"

fail() { echo "handover: $*" >&2; exit 1; }

# Leap validates the HTTP Host header against its listening address, so
# requests arriving via a remapped host port must forge 0.0.0.0:8888.
leap_info() {
    curl --fail --silent --max-time 10 -X POST "$LEAP_API/v1/chain/get_info" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d '{}'
}
shadow_head() {
    curl --fail --silent --max-time 10 -X POST "$SHADOW_RPC/" \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["head_block_num"])'
}
chain_rpc_url() {
    "$NETWORK_RUNNER" control list-rpcs --endpoint="$RUNNER_ENDPOINT" 2>/dev/null \
        | sed $'s/\033\[[0-9;]*m//g' \
        | grep -oE 'http://127\.0\.0\.1:[0-9]+/ext/bc/[A-Za-z0-9]+' | head -1
}
rpc_call() {
    curl --fail --silent --max-time 15 -X POST "$1" \
        -H 'Content-Type: application/json' -d "$2"
}

cmd_start() {
    [[ ! -e "$WORK_DIR" ]] || fail "work directory exists: $WORK_DIR (run stop first)"
    mkdir -p "$WORK_DIR"
    echo "handover: building the replay binary on the host..."
    export PATH="$HOME/.cargo/bin:$PATH"
    (cd "$REPO_ROOT" && cargo build --locked --release --example xpr_blocklog_replay) || fail "replay build failed"
    [[ -x "$PULSEVM_REPLAY_BIN" ]] || fail "replay binary missing: $PULSEVM_REPLAY_BIN (run-handover.sh builds this first)"
    (cd "$SCRIPT_DIR" && docker compose -f compose.yaml up --detach xpr-producer)
    echo "handover: waiting for the Leap producer..."
    for _ in $(seq 1 90); do leap_info >/dev/null 2>&1 && break; sleep 1; done
    leap_info >/dev/null || fail "Leap producer did not become ready"
    (cd "$SCRIPT_DIR" && docker compose -f compose.yaml up --detach shadow)
    echo "handover: shadowing until height $TERMINAL_HEIGHT..."
    while true; do
        head="$(shadow_head 2>/dev/null || echo 0)"
        echo "handover: shadow head $head / $TERMINAL_HEIGHT"
        [[ "$head" -ge "$TERMINAL_HEIGHT" ]] && break
        sleep 5
    done
    cmd_halt
}

cmd_halt() {
    # H is the snapshot height, not the live head: blocks produced between
    # the snapshot and the stop are stragglers past the declared cutoff and
    # are ignored, exactly as post-H XPR blocks are ignored by the A-Chain.
    echo "handover: snapshotting, then halting the producer (models the BP halt commitment)..."
    snap_json="$(curl --fail --silent --max-time 30 -X POST "$LEAP_API/v1/producer/create_snapshot" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d '{}')"
    snap="$(printf '%s' "$snap_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["snapshot_name"])')"
    H_ID="$(printf '%s' "$snap_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_id"])')"
    [[ -n "$snap" && -n "$H_ID" ]] || fail "snapshot request failed"
    H="$(curl --fail --silent --max-time 15 -X POST "$LEAP_API/v1/chain/get_block" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' \
        -d "{\"block_num_or_id\":\"$H_ID\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["block_num"])')"
    echo "$H" >"$WORK_DIR/H"
    echo "$H_ID" >"$WORK_DIR/H_ID"
    mountpoint="$(docker volume inspect --format '{{.Mountpoint}}' pulsevm-handover_leap-data)"
    if [[ "$snap" = /* ]]; then
        echo "$snap" >"$WORK_DIR/snapshot"
    else
        echo "$mountpoint/$snap" >"$WORK_DIR/snapshot"
    fi
    (cd "$SCRIPT_DIR" && docker compose -f compose.yaml stop xpr-producer)
    echo "handover: halted; H=$H id=$H_ID; waiting for the shadow to absorb H..."
    for _ in $(seq 1 36); do
        shadow_h="$(shadow_head 2>/dev/null || echo 0)"
        [[ "$shadow_h" -ge "$H" ]] && break
        sleep 5
    done
    shadow_h="$(shadow_head)"
    [[ "$shadow_h" -ge "$H" ]] || fail "shadow never absorbed H=$H (stuck at $shadow_h)"
    echo "handover: shadow absorbed H (shadow $shadow_h); checkpointing..."
    cmd_checkpoint
}

cmd_checkpoint() {
    # No --xpr-core: preflight and the deferred sidecar are mainnet
    # provenance guards, and the fixture chain has no deferred activity.
    # The sidecar-gated validate-mainnet-export.sh is therefore skipped
    # here; import-time manifest checks still apply. Mainnet exports must
    # keep the full validation path.
    # The export work dir must sit below /tmp for the nodeos-docker adapter.
    export_dir="$(mktemp -d /tmp/pulsevm-handover-export.XXXXXX)"
    echo "$export_dir" >"$WORK_DIR/export-dir"
    (cd "$REPO_ROOT" && tools/xpr-chainbase-export/export.sh \
        --nodeos tools/xpr-chainbase-export/localnet/nodeos-docker \
        --snapshot "$(cat "$WORK_DIR/snapshot")" \
        --work-dir "$export_dir" \
        --source-revision leap-5.0.3) || fail "export failed"
    (cd "$REPO_ROOT" && cargo run --locked -p pulsevm_database --example xpr_import_check -- \
        "$export_dir/state-history/chain_state_history.log" \
        "$export_dir/arena" \
        "$export_dir/migration.snapshot") || fail "checkpoint import failed"
    echo "handover: checkpoint ready: $export_dir/migration.snapshot"
    cmd_boot "$export_dir/migration.snapshot"
}

cmd_boot() {
    checkpoint="${1:?checkpoint required}"
    H="$(cat "$WORK_DIR/H")"
    H_ID="$(cat "$WORK_DIR/H_ID")"
    echo "handover: booting the five-node network from the H=$H checkpoint (background)..."
    (cd "$REPO_ROOT" && \
        METALGO_EXEC_PATH="${METALGO_EXEC_PATH:-$REPO_ROOT/../metalgo/build/metalgo}" \
        PULSEVM_MIGRATION_CHECKPOINT="$checkpoint" \
        PULSEVM_EC2_RUN_DIR="$WORK_DIR/five-node" \
        PULSEVM_VERIFY_FIVE_NODE=false \
        scripts/run-local.sh >"$WORK_DIR/five-node.log" 2>&1 &
        echo $! >"$WORK_DIR/five-node.pid")
    echo "handover: waiting for the new network to pass H..."
    rpc_url=""
    for _ in $(seq 1 60); do
        rpc_url="$(chain_rpc_url || true)"
        [[ -n "$rpc_url" ]] || { sleep 5; continue; }
        new_head="$(rpc_call "$rpc_url" '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' 2>/dev/null \
            | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["head_block_num"])' 2>/dev/null || echo 0)"
        [[ "$new_head" -gt "$H" ]] && break
        sleep 5
    done
    [[ "$new_head" -gt "$H" ]] || fail "new network never passed H=$H (see $WORK_DIR/five-node.log)"
    next_id="$(rpc_call "$rpc_url" '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getBlock","params":{"block_num_or_id":'"$((H + 1))"'}}' \
        | python3 -c 'import json,sys; b=json.load(sys.stdin)["result"]; print(b["previous"], b["block_num"])')"
    [[ "$next_id" == "$H_ID $((H + 1))" ]] || fail "continuity broken: block H+1 parent is $next_id, expected parent $H_ID"
    old_chain="$(shadow_head >/dev/null 2>&1; curl --fail --silent --max-time 10 -X POST "$SHADOW_RPC/" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["chain_id"])' 2>/dev/null || echo stopped)"
    new_chain="$(rpc_call "$rpc_url" '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["chain_id"])')"
    echo "handover: PASS: block $((H + 1)) builds on halt block $H_ID; shadow chain $old_chain -> new chain $new_chain"
    echo "handover: new network RPC: $rpc_url (left running; run stop to tear down)"
}

cmd_stop() {
    if [[ -f "$WORK_DIR/five-node.pid" ]]; then
        kill "$(cat "$WORK_DIR/five-node.pid")" 2>/dev/null || true
        pkill -f metal-network-runner 2>/dev/null || true
    fi
    (cd "$SCRIPT_DIR" && docker compose -f compose.yaml down --volumes 2>/dev/null) || true
    rm -rf "$WORK_DIR"
    echo "handover: stopped"
}

case "${1:-}" in
    start) cmd_start ;;
    stop) cmd_stop ;;
    *) echo "usage: run-handover.sh start|stop" >&2
       echo "env: TERMINAL_HEIGHT (default 1200, ~10 min at 0.5s blocks)," >&2
       echo "     HANDOVER_WORK_DIR, XPR_CORE_DIR, METALGO_EXEC_PATH," >&2
       echo "     LEAP_HTTP_PORT, SHADOW_RPC_PORT" >&2
       exit 2 ;;
esac
