#!/usr/bin/env bash
# Rehearse the shadow-then-promote handover: a three-node Leap network runs
# XPR under consensus, PulseVM shadows it, the whole XPR network halts at
# TERMINAL_HEIGHT, and a five-node PulseVM network boots from the
# checkpointed shadow state, takes its own first transaction, and continues
# at H+1.
#
# Phase 2 note: promotion currently re-identifies the chain (the migration
# genesis commits to the checkpoint hash). Same-ID in-process promotion is
# future work; this rehearsal validates follow, halt, checkpoint, boot,
# parent linkage, and liveness.
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
readonly TERMINAL_HEIGHT="${TERMINAL_HEIGHT:-300}"
readonly WORK_DIR="${HANDOVER_WORK_DIR:-/tmp/pulsevm-handover}"
readonly LEAP_API="http://127.0.0.1:${LEAP_HTTP_PORT:-8888}"
readonly LEAP_V1_API="http://127.0.0.1:${LEAP_V1_HTTP_PORT:-18881}"
readonly LEAP_V2_API="http://127.0.0.1:${LEAP_V2_HTTP_PORT:-18882}"
readonly SHADOW_RPC="http://127.0.0.1:${SHADOW_RPC_PORT:-9660}"
readonly XPR_CORE_DIR="${XPR_CORE_DIR:-/src/antelope-leap}"
readonly NETWORK_RUNNER="${METAL_NETWORK_RUNNER_PATH:-$REPO_ROOT/../metal-network-runner/bin/metal-network-runner}"
runner_endpoint() {
    # Resolved lazily (not readonly at load): cmd_boot exports the rehearsal
    # endpoint (18080) after startup, and polling must follow it, not the
    # load-time default.
    printf '%s' "${METAL_NETWORK_RUNNER_ENDPOINT:-127.0.0.1:8081}"
}

# Set early so every compose invocation (including stop) interpolates.
export PULSEVM_REPLAY_BIN="${PULSEVM_REPLAY_BIN:-$REPO_ROOT/target/release/examples/xpr_blocklog_replay}"
# Host Rust toolchain for the checkpoint importer and the replay build.
export PATH="$HOME/.cargo/bin:$PATH"

fail() {
    echo "handover: $*" >&2
    # Never leave a booted five-node network behind a failed run: take the
    # supervisor down with us (nodes stay up only after an explicit PASS).
    if [[ -f "${WORK_DIR:-/nonexistent}/five-node.pid" ]]; then
        kill "$(cat "$WORK_DIR/five-node.pid")" 2>/dev/null || true
        pkill -f 'metal-network-runne[r]' 2>/dev/null || true
    fi
    if [[ -f "${WORK_DIR:-/nonexistent}/shadow.pid" ]]; then
        kill "$(cat "$WORK_DIR/shadow.pid")" 2>/dev/null || true
    fi
    exit 1
}

# Leap validates the HTTP Host header against its listening address, so
# requests arriving via a remapped host port must forge 0.0.0.0:8888.
leap_node_info() {
    curl --fail --silent --max-time 10 -X POST "$1/v1/chain/get_info" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d '{}'
}
leap_info() {
    leap_node_info "$LEAP_API"
}
# "head lib" for one XPR node; empty on failure.
leap_head_lib() {
    leap_node_info "$1" 2>/dev/null \
        | python3 -c 'import json,sys; i=json.load(sys.stdin); print(i["head_block_num"], i["last_irreversible_block_num"])' 2>/dev/null || true
}
# POST to a Leap API path with the forged Host header Leap requires.
leap_post() {
    curl --fail --silent --max-time 15 -X POST "$1$2" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d "$3"
}
# Submit an issueTx-format body to Leap's send_transaction; prints the txid.
# Fails LOUD: curl errors used to be swallowed by --fail --silent inside a
# pipefail pipeline, so a duplicate or rejected transaction killed the run
# via a bare set -e exit with no diagnosis (stale chain data from a reused
# compose volume made every rerun hit "account already exists"). Retries
# cover transient connection stalls; a persistent rejection aborts here.
leap_send() {
    local body send_out attempt
    body="$(printf '%s' "$1" | python3 -c 'import json,sys; p=json.load(sys.stdin)["params"]; print(json.dumps({"signatures":p["signatures"],"compression":"none","packed_context_free_data":p["packed_context_free_data"],"packed_trx":p["packed_trx"]}))')" \
        || { echo "handover: leap_send: refusing to submit an unparseable issueTx body" >&2; return 1; }
    for attempt in 1 2 3; do
        send_out="$(curl --fail --silent --show-error --max-time 15 -X POST "$LEAP_API/v1/chain/send_transaction" \
            -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d "$body" 2>&1)" && break
        echo "handover: leap_send attempt $attempt failed: $send_out" >&2
        sleep 3
    done
    [[ -n "${send_out:-}" ]] || { echo "handover: leap_send: send_transaction unreachable after 3 attempts" >&2; return 1; }
    printf '%s' "$send_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["transaction_id"])' 2>/dev/null \
        || { echo "handover: leap_send: send_transaction rejected the transaction: $send_out" >&2; return 1; }
}
# "chain_id head_num head_id" for a Leap node. Retries: callers feed the
# result straight into arithmetic under `set -e`, so a single transient
# read (node serving get_info mid-block) must not silently kill the run.
leap_chain_head() {
    local out attempt
    for attempt in 1 2 3 4 5; do
        out="$(leap_node_info "$1" 2>/dev/null | python3 -c 'import json,sys; i=json.load(sys.stdin); print(i["chain_id"], i["head_block_num"], i["head_block_id"])' 2>/dev/null)" && [[ -n "$out" ]] && break
        out=""
        sleep 2
    done
    [[ -n "${out:-}" ]] || { echo "handover: leap_chain_head: get_info unreadable after 5 attempts" >&2; return 1; }
    printf '%s\n' "$out"
}
shadow_head() {
    curl --fail --silent --max-time 10 -X POST "$SHADOW_RPC/" \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["head_block_num"])'
}
chain_rpc_url() {
    # Bound the call: a dead endpoint otherwise stalls each poll iteration.
    # Uses the runner's own dial/request timeouts instead of GNU `timeout`,
    # which does not exist on macOS (without this, discovery silently
    # returns empty on Mac hosts and every boot dies with "RPC never came
    # up" while the network underneath is healthy).
    # list-rpcs reports the full handler URL including the /rpc suffix: keep
    # it, since the bare /ext/bc/<id> base answers 404.
    "$NETWORK_RUNNER" control list-rpcs --endpoint="$(runner_endpoint)" \
        --dial-timeout 5s --request-timeout 15s 2>/dev/null \
        | sed $'s/\033\[[0-9;]*m//g' \
        | grep -oE 'http://127\.0\.0\.1:[0-9]+/ext/bc/[A-Za-z0-9]+/rpc' | head -1
}
rpc_call() {
    curl --fail --silent --max-time 15 -X POST "$1" \
        -H 'Content-Type: application/json' -d "$2"
}

cmd_start() {
    [[ ! -e "$WORK_DIR" ]] || fail "work directory exists: $WORK_DIR (run stop first)"
    mkdir -p "$WORK_DIR"
    echo "handover: building the replay binary and the probe-tx tool on the host..."
    (cd "$REPO_ROOT" && cargo build --locked --release --example xpr_blocklog_replay) || fail "replay build failed"
    [[ -x "$PULSEVM_REPLAY_BIN" ]] || fail "replay binary missing: $PULSEVM_REPLAY_BIN (run-handover.sh builds this first)"
    (cd "$REPO_ROOT" && cargo build --locked --release -p pulsevm_core --example make_probe_tx) || fail "probe tool build failed"
    PROBE_BIN="$REPO_ROOT/target/release/examples/make_probe_tx"
    [[ -x "$PROBE_BIN" ]] || fail "probe tool missing: $PROBE_BIN"
    # A rehearsal proves a halt at H on a FRESH chain: drop the compose
    # volumes first. Without this, reruns resume the previous run's chain
    # from its named volume, so traffic/boundary account creation collides
    # with already-existing accounts ("account already exists") and the
    # terminal height is already passed — a resumed chain, not a migration.
    (cd "$SCRIPT_DIR" && docker compose -f compose.yaml down --volumes 2>/dev/null) || true
    (cd "$SCRIPT_DIR" && docker compose -f compose.yaml up --detach xpr-producer)
    echo "handover: waiting for the Leap producer..."
    for _ in $(seq 1 90); do leap_info >/dev/null 2>&1 && break; sleep 1; done
    leap_info >/dev/null || fail "Leap producer did not become ready"
    (cd "$SCRIPT_DIR" && docker compose -f compose.yaml up --detach xpr-validator-1 xpr-validator-2)
    echo "handover: waiting for the two validators to answer..."
    for _ in $(seq 1 90); do
        leap_node_info "$LEAP_V1_API" >/dev/null 2>&1 && leap_node_info "$LEAP_V2_API" >/dev/null 2>&1 && break
        sleep 1
    done
    leap_node_info "$LEAP_V1_API" >/dev/null || fail "validator 1 did not become ready"
    leap_node_info "$LEAP_V2_API" >/dev/null || fail "validator 2 did not become ready"
    echo "handover: waiting for three-node consensus (equal head and LIB on all nodes)..."
    converged=false
    for _ in $(seq 1 60); do
        p="$(leap_head_lib "$LEAP_API")"
        v1="$(leap_head_lib "$LEAP_V1_API")"
        v2="$(leap_head_lib "$LEAP_V2_API")"
        echo "handover: producer [$p] validator-1 [$v1] validator-2 [$v2]"
        if [[ -n "$p" && "$p" == "$v1" && "$p" == "$v2" ]]; then
            head="${p%% *}"
            if [[ "$head" -ge 10 ]]; then
                echo "handover: consensus at head $head"
                converged=true
                break
            fi
        fi
        sleep 2
    done
    [[ "$converged" == true ]] || fail "XPR nodes never reached consensus"
    # Seed pre-halt traffic the equivalence gate re-checks after promotion:
    # three accounts (one born under a rotated key) plus a live key rotation.
    # These land hundreds of blocks before N, hence deep in irreversibility.
    echo "handover: seeding pre-halt traffic on XPR..."
    read -r TRAFFIC_WIF TRAFFIC_PUB <<<"$("$PROBE_BIN" newkey)"
    echo "$TRAFFIC_WIF $TRAFFIC_PUB" >"$WORK_DIR/traffic-key"
    read -r leap_chain leap_head leap_head_id <<<"$(leap_chain_head "$LEAP_API")"
    leap_prefix="$(python3 -c "import sys; print(int.from_bytes(bytes.fromhex('$leap_head_id')[8:12], 'little'))")"
    leap_exp="$(($(date +%s) + 1800))"
    leap_ref="$((leap_head & 0xffff))"
    # Fixture dev key (disposable rehearsal only, never used on mainnet).
    DEV_KEY="${PULSEVM_PRODUCER_KEY:-5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3}"
    submit_leap() {
        leap_send "$("$PROBE_BIN" "$@")"
    }
    echo "handover: traffic t1: $(submit_leap newaccount "$leap_chain" "$DEV_KEY" "$leap_ref" "$leap_prefix" "$leap_exp" t1 "$TRAFFIC_PUB")"
    echo "handover: traffic t2: $(submit_leap newaccount "$leap_chain" "$DEV_KEY" "$leap_ref" "$leap_prefix" "$leap_exp" t2)"
    echo "handover: traffic t3: $(submit_leap newaccount "$leap_chain" "$DEV_KEY" "$leap_ref" "$leap_prefix" "$leap_exp" t3)"
    echo "handover: traffic rotate t3: $(submit_leap updateauth "$leap_chain" "$DEV_KEY" "$leap_ref" "$leap_prefix" "$leap_exp" t3 active owner "$TRAFFIC_PUB")"
    echo "handover: waiting for the traffic accounts to exist..."
    for _ in $(seq 1 60); do
        leap_post "$LEAP_API" /v1/chain/get_account '{"account_name":"t1"}' >/dev/null 2>&1 \
        && leap_post "$LEAP_API" /v1/chain/get_account '{"account_name":"t2"}' >/dev/null 2>&1 \
        && leap_post "$LEAP_API" /v1/chain/get_account '{"account_name":"t3"}' >/dev/null 2>&1 && break
        sleep 2
    done
    python3 -c '
import json, subprocess, sys
api, out = sys.argv[1], sys.argv[2]
accts = {}
for name in ["eosio", "t1", "t2", "t3"]:
    p = subprocess.run(["curl", "--fail", "--silent", "--max-time", "15", "-X", "POST",
                        api + "/v1/chain/get_account", "-H", "Content-Type: application/json",
                        "-H", "Host: 0.0.0.0:8888", "-d", json.dumps({"account_name": name})],
                       capture_output=True, text=True)
    p.check_returncode()
    accts[name] = json.loads(p.stdout)
json.dump(accts, open(out, "w"), indent=1)
' "$LEAP_API" "$WORK_DIR/pre-halt-accounts.json" || fail "pre-halt state capture failed"
    echo "handover: pre-halt state captured for eosio,t1,t2,t3"
    # Native shadow (Mac hosts): the host-built replay binary is Mach-O and
    # cannot run in the Linux shadow container, so it starts after the halt
    # on a staged static copy of the frozen block log instead of following
    # live. Real-time follow is already proven by containerized rehearsals.
    if [[ "${XPR_SHADOW_NATIVE:-0}" == "1" ]]; then
        echo "handover: native shadow deferred until halt (static log replay)"
    else
        (cd "$SCRIPT_DIR" && docker compose -f compose.yaml up --detach shadow)
    fi
    echo "handover: shadowing until height $TERMINAL_HEIGHT..."
    if [[ "${XPR_SHADOW_NATIVE:-0}" == "1" ]]; then
        # No live shadow here; wait for XPR itself to reach the terminal
        # height, then halt. The static native shadow absorbs H afterwards.
        while true; do
            head="$(leap_head_lib "$LEAP_API" 2>/dev/null | cut -d' ' -f1)"
            head="${head:-0}"
            echo "handover: XPR head $head / $TERMINAL_HEIGHT"
            [[ "$head" -ge "$TERMINAL_HEIGHT" ]] && break
            sleep 5
        done
    else
        while true; do
            head="$(shadow_head 2>/dev/null || echo 0)"
            echo "handover: shadow head $head / $TERMINAL_HEIGHT"
            [[ "$head" -ge "$TERMINAL_HEIGHT" ]] && break
            sleep 5
        done
    fi
    cmd_halt
}

cmd_halt() {
    # H is the snapshot height, not the live head: blocks produced between
    # the snapshot and the stop are stragglers past the declared cutoff and
    # are ignored, exactly as post-H XPR blocks are ignored by the A-Chain.
    echo "handover: snapshotting, then halting the producer (models the BP halt commitment)..."
    # Boundary traffic, phase 1: customer transactions that must land on the
    # OLD network (at or below H). They are submitted now and driven to
    # irreversibility before the snapshot, so the audit can later prove none
    # were lost in the swap.
    read -r b_leap_chain b_leap_head b_leap_head_id <<<"$(leap_chain_head "$LEAP_API")"
    b_prefix="$(python3 -c "import sys; print(int.from_bytes(bytes.fromhex('$b_leap_head_id')[8:12], 'little'))")"
    b_exp="$(($(date +%s) + 1800))"
    b_ref="$((b_leap_head & 0xffff))"
    b_dev="${PULSEVM_PRODUCER_KEY:-5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3}"
    phase1='[]'
    for cname in c1 c2 c3 c4 c5; do
        txid="$(leap_send "$("$PROBE_BIN" newaccount "$b_leap_chain" "$b_dev" "$b_ref" "$b_prefix" "$b_exp" "$cname")")" \
            || fail "boundary submit $cname failed (see leap_send diagnosis above)"
        echo "handover: boundary tx $cname: $txid"
        phase1="$(printf '%s' "$phase1" | python3 -c "import json,sys; l=json.load(sys.stdin); l.append({\"name\": \"$cname\", \"txid\": \"$txid\"}); print(json.dumps(l))")"
    done
    echo "handover: waiting for boundary traffic to exist and go irreversible..."
    for _ in $(seq 1 60); do
        leap_post "$LEAP_API" /v1/chain/get_account '{"account_name":"c5"}' >/dev/null 2>&1 && break
        sleep 2
    done
    leap_post "$LEAP_API" /v1/chain/get_account '{"account_name":"c5"}' >/dev/null \
        || fail "boundary traffic never landed"
    for _ in $(seq 1 60); do
        b_now="$(leap_head_lib "$LEAP_API")"
        [[ "${b_now##* }" -ge "$b_leap_head" ]] && break
        sleep 2
    done
    [[ "${b_now##* }" -ge "$b_leap_head" ]] || fail "boundary traffic never went irreversible"
    python3 -c 'import json,sys; json.dump({"submit_head": int(sys.argv[1]), "phase1": json.loads(sys.argv[2]), "phase3": []}, open(sys.argv[3], "w"), indent=1)' \
        "$b_leap_head" "$phase1" "$WORK_DIR/boundary-txns.json"
    echo "handover: confirming boundary traffic landed pre-halt..."
    python3 - "$WORK_DIR/boundary-txns.json" "$LEAP_API" <<'PYEOF' || fail "boundary traffic missing pre-halt"
import json, sys, time, urllib.request
def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Host": "0.0.0.0:8888"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)
rec = json.load(open(sys.argv[1]))
api = sys.argv[2]
want = {t["txid"] for t in rec["phase1"]}
lo = rec["submit_head"]
# One clean pass is the norm; retry a few rounds so a transient read
# (node serving a block while it is still being built) cannot fail a
# healthy handover, while genuinely lost traffic still fails closed.
missing = []
for attempt in range(4):
    hi = post(api + "/v1/chain/get_info", {})["head_block_num"]
    found = set()
    for num in range(lo, hi + 1):
        block = post(api + "/v1/chain/get_block", {"block_num_or_id": str(num)})
        for t in block.get("transactions", []):
            trx = t.get("trx", t)
            tid = trx.get("id") if isinstance(trx, dict) else trx
            if isinstance(tid, str) and len(tid) == 64:
                found.add(tid)
    missing = sorted(w for w in want if w not in found)
    print(f"  confirm pass {attempt + 1}: [{lo},{hi}] found {len(found)} want {len(want)}")
    if not missing:
        break
    time.sleep(10)
if missing:
    print(f"  missing pre-halt: {missing}")
    sys.exit(1)
rec["old_ids"] = sorted(found)
rec["phase1_hi"] = hi
json.dump(rec, open(sys.argv[1], "w"), indent=1)
print(f"  phase 1 confirmed in old chain blocks [{lo},{hi}]")
PYEOF
    echo "handover: boundary phase 1 sealed at LIB (submit head $b_leap_head)"
    # The migration anchor must be an empty block (no transactions, no
    # schedule change) for the id-exact attach. Snapshot heads usually are,
    # but a boundary transaction can land in one; retry until empty.
    snap=""
    H=""
    H_ID=""
    for _ in $(seq 1 8); do
        snap_json="$(curl --fail --silent --max-time 30 -X POST "$LEAP_API/v1/producer/create_snapshot" \
            -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d '{}')"
        snap="$(printf '%s' "$snap_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["snapshot_name"])')"
        H_ID="$(printf '%s' "$snap_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_id"])')"
        [[ -n "$snap" && -n "$H_ID" ]] || fail "snapshot request failed"
        H="$(curl --fail --silent --max-time 15 -X POST "$LEAP_API/v1/chain/get_block" \
            -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' \
            -d "{\"block_num_or_id\":\"$H_ID\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["block_num"])')"
        block_json="$(curl --fail --silent --max-time 15 -X POST "$LEAP_API/v1/chain/get_block" \
            -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' \
            -d "{\"block_num_or_id\":\"$H\"}")" || fail "get_block H=$H failed"
        if printf '%s' "$block_json" | python3 -c 'import json,sys; b=json.load(sys.stdin); sys.exit(0 if (not b.get("transactions") and not b.get("new_producers")) else 1)'; then
            echo "handover: snapshot boundary H=$H is empty"
            break
        fi
        echo "handover: snapshot boundary H=$H carries traffic; retrying snapshot..."
        snap=""
        H=""
        H_ID=""
        sleep 2
    done
    [[ -n "$H" && -n "$H_ID" && -n "$snap" ]] || fail "no empty snapshot boundary after retries"
    echo "$H" >"$WORK_DIR/H"
    echo "$H_ID" >"$WORK_DIR/H_ID"
    # The migration anchor needs the id-exact source block. Fetch it while
    # the producer still serves reads.
    curl --fail --silent --max-time 15 -X POST "$LEAP_API/v1/chain/get_block" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' \
        -d "{\"block_num_or_id\":\"$H\"}" >"$WORK_DIR/block-H.json" || fail "get_block H=$H failed"
    mountpoint="$(docker volume inspect --format '{{.Mountpoint}}' pulsevm-handover_leap-data)"
    # nodeos reports container paths: absolute names start at its /data dir,
    # which is the shared leap-data volume on the host.
    if [[ "$snap" = /data/* ]]; then
        snap_host="$mountpoint/${snap#/data/}"
    elif [[ "$snap" = /* ]]; then
        snap_host="$snap"
    else
        snap_host="$mountpoint/$snap"
    fi
    # The volume is root-owned, so the export (running host checks as the
    # local user) cannot read the snapshot in place: stage a readable copy
    # in the work dir, which is also bind-mounted into export containers.
    docker run --rm -v pulsevm-handover_leap-data:/d:ro -v "$WORK_DIR:/out" ubuntu:24.04 \
        cp "/d/snapshots/$(basename "$snap_host")" /out/snapshot.bin \
        || fail "snapshot stage failed"
    echo "$WORK_DIR/snapshot.bin" >"$WORK_DIR/snapshot"
    # Full network halt: stop the producer and both validators. The XPR
    # chain must freeze: no new blocks may appear in the shared block log
    # after the stop.
    (cd "$SCRIPT_DIR" && docker compose -f compose.yaml stop xpr-producer xpr-validator-1 xpr-validator-2)
    # The block log lives in a root-owned Docker volume: read its size from
    # a throwaway container rather than stat(1) on the host mountpoint.
    blocks_bytes() {
        docker run --rm -v pulsevm-handover_leap-data:/d:ro ubuntu:24.04 stat -c '%s' /d/blocks/blocks.log
    }
    size_before="$(blocks_bytes)"
    echo "handover: XPR network stopped at H=$H; proving the freeze (blocks.log $size_before bytes)..."
    sleep 10
    size_after="$(blocks_bytes)"
    [[ "$size_before" == "$size_after" ]] \
        || fail "XPR network did not freeze: blocks.log grew $size_before -> $size_after after the stop"
    echo "handover: halted and frozen; H=$H id=$H_ID; waiting for the shadow to absorb H..."
    if [[ "${XPR_SHADOW_NATIVE:-0}" == "1" ]]; then
        echo "handover: staging frozen block log for the native shadow..."
        docker run --rm -v pulsevm-handover_leap-data:/d:ro -v "$WORK_DIR:/out" ubuntu:24.04 \
            cp -r /d/blocks /out/leap-blocks || fail "block log stage failed"
        XPR_REPLAY_FOLLOW=1 \
        XPR_REPLAY_RPC_BIND="127.0.0.1:${SHADOW_RPC_PORT:-9660}" \
        XPR_REPLAY_GENESIS_FILE="$REPO_ROOT/tools/xpr-chainbase-export/localnet/genesis.json" \
            "$PULSEVM_REPLAY_BIN" "$WORK_DIR/leap-blocks" "$WORK_DIR/shadow-arena" \
            >"$WORK_DIR/shadow.log" 2>&1 &
        echo "$!" >"$WORK_DIR/shadow.pid"
    fi
    for _ in $(seq 1 36); do
        shadow_h="$(shadow_head 2>/dev/null || echo 0)"
        [[ "$shadow_h" -ge "$H" ]] && break
        sleep 5
    done
    shadow_h="$(shadow_head)"
    [[ "$shadow_h" -ge "$H" ]] || fail "shadow never absorbed H=$H (stuck at $shadow_h)"
    echo "handover: shadow absorbed H (shadow $shadow_h); checkpointing..."
    # The replay's job ends here: it absorbed the terminal block, and the
    # checkpoint is sealed from static artifacts. Stop it explicitly — from
    # this point only the new network may write.
    if [[ "${XPR_SHADOW_NATIVE:-0}" == "1" && -f "$WORK_DIR/shadow.pid" ]]; then
        kill "$(cat "$WORK_DIR/shadow.pid")" 2>/dev/null || true
    else
        (cd "$SCRIPT_DIR" && docker compose -f compose.yaml stop shadow)
    fi
    echo "handover: replay stopped; only the new network writes from here"
    cmd_checkpoint
}

cmd_checkpoint() {
    # No --xpr-core: preflight and the deferred sidecar are mainnet
    # provenance guards, and the fixture chain has no deferred activity.
    # The sidecar-gated validate-mainnet-export.sh is therefore skipped
    # here; import-time manifest checks still apply. Mainnet exports must
    # keep the full validation path.
    # The export work dir must sit below /tmp for the nodeos-docker adapter.
    # mktemp -u reserves the name without creating it: export.sh requires a
    # non-existing work dir.
    export_dir="$(mktemp -du /tmp/pulsevm-handover-export.XXXXXX)"
    echo "$export_dir" >"$WORK_DIR/export-dir"
    (cd "$REPO_ROOT" && \
        XPR_NODEOS_IMAGE="${XPR_NODEOS_IMAGE:-pulsevm-leap:5.0.3-amd64}" \
        tools/xpr-chainbase-export/export.sh \
        --nodeos "$SCRIPT_DIR/nodeos-docker-handover" \
        --snapshot "$(cat "$WORK_DIR/snapshot")" \
        --work-dir "$export_dir" \
        --source-revision leap-5.0.3) || fail "export failed"
    (cd "$REPO_ROOT" && cargo run --locked -p pulsevm_database --example xpr_import_check -- \
        "$export_dir/state-history/chain_state_history.log" \
        "$export_dir/arena" \
        "$export_dir/migration.snapshot") || fail "checkpoint import failed"
    # Anchor the id-exact source block so new nodes adopt H as their tip
    # instead of failing on an empty block log.
    (cd "$REPO_ROOT" && cargo build --locked --release --example xpr_attach_source_block) \
        || fail "attach tool build failed"
    manifest="$export_dir/migration.snapshot.manifest.json"
    # The halt ceremony signs the freeze over H with the old schedule's key;
    # the new network verifies this commitment before promoting.
    # Fixture dev key doubles as the old schedule key (rehearsal only).
    halt_key="${DEV_KEY:-${PULSEVM_PRODUCER_KEY:-5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3}}"
    # HALT_V2=1 exercises the checkpoint-bound commitment plus the weighted
    # roster path with a self-contained single-member ceremony: roster
    # {eosio, fixture key, 1} satisfies the 2/3 quorum on its own. The
    # fixture chain carries no producers table, so the state cross-check
    # logs its skip exactly as designed for table-less fixtures.
    if [[ "${HALT_V2:-0}" == "1" ]]; then
        roster_key="$(jq -er '.initial_key' "$REPO_ROOT/tools/xpr-chainbase-export/localnet/genesis.json")"
        printf '[{"producer":"eosio","key":"%s","weight":1}]' "$roster_key" >"$WORK_DIR/roster.json"
        "$REPO_ROOT/target/release/examples/xpr_attach_source_block" \
            "$manifest" "$WORK_DIR/block-H.json" "$manifest.attached" \
            --halt-key-v2 "$halt_key" --halt-roster "$WORK_DIR/roster.json" \
            || fail "source block attach failed (H must be an empty block)"
    else
        "$REPO_ROOT/target/release/examples/xpr_attach_source_block" \
            "$manifest" "$WORK_DIR/block-H.json" "$manifest.attached" \
            --halt-key "$halt_key" \
            || fail "source block attach failed (H must be an empty block)"
    fi
    mv "$manifest.attached" "$manifest"
    echo "handover: halt commitment signed over H=$H"
    echo "$export_dir/migration.snapshot" >"$WORK_DIR/checkpoint"
    echo "handover: checkpoint ready: $export_dir/migration.snapshot"
    cmd_boot "$export_dir/migration.snapshot"
}

cmd_boot() {
    checkpoint="${1:?checkpoint required}"
    H="$(cat "$WORK_DIR/H")"
    H_ID="$(cat "$WORK_DIR/H_ID")"
    echo "handover: booting the five-node network from the H=$H checkpoint (background)..."
    # Dedicated plugin dir: the repo build/plugins file may be mapped by
    # another live network on a shared host (ETXTBSY on overwrite).
    mkdir -p "$WORK_DIR/plugins"
    # Rehearsal runner ports avoid the host status server (:8080) and any
    # other live network on this box. Override with PULSEVM_RUNNER_PORT /
    # PULSEVM_RUNNER_GATEWAY_PORT where those defaults are taken.
    export METAL_NETWORK_RUNNER_PORT=":${PULSEVM_RUNNER_PORT:-18080}"
    export METAL_NETWORK_RUNNER_GATEWAY_PORT=":${PULSEVM_RUNNER_GATEWAY_PORT:-18081}"
    export METAL_NETWORK_RUNNER_ENDPOINT="127.0.0.1:${PULSEVM_RUNNER_PORT:-18080}"
    # Node ports are reassigned when taken, with dynamic allocation as the
    # backstop: the rehearsal shares the host with other live networks.
    export RUNNER_REASSIGN_PORTS_IF_USED=true
    export PULSEVM_RUNNER_START_EXTRA_ARGS="--dynamic-ports --request-timeout 10m"
    # The fixture checkpoint's system account is eosio, not pulse: the new
    # network must adopt the fixture identities, with the fixture dev key
    # (disposable rehearsal only, never used on mainnet).
    export PULSEVM_SYSTEM_ACCOUNT="eosio"
    export PULSEVM_PRODUCER_NAME="eosio"
    export PULSEVM_PRODUCER_KEY="5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
    # The migration restore starts a new producer schedule seeded from the
    # migration genesis initial key, so the new chain must be seeded with a
    # key the nodes hold. Derive it from the same fixture genesis the Leap
    # producer boots from: with a foreign key every build fails closed at the
    # signing gate and the new network never passes H.
    export PULSEVM_GENESIS_INITIAL_KEY="$(jq -er '.initial_key' "$REPO_ROOT/tools/xpr-chainbase-export/localnet/genesis.json")"
    # Fail fast when the runner endpoint is already bound (e.g. a status
    # server or a stale network squats the default :18080): otherwise the
    # boot below burns the whole RPC wait and dies with a mystery timeout.
    # A few spaced attempts: host services on shared boxes come and go, and
    # a transient squatter must not kill an otherwise healthy rehearsal.
    bound=0
    for _ in 1 2 3; do
        if python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(2); sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)' "${PULSEVM_RUNNER_PORT:-18080}"; then
            bound=1
        else
            bound=0
            break
        fi
        sleep 10
    done
    # NOTE: the connect_ex probe must compare `== 0` (0 means the connect
    # succeeded, i.e. the port IS bound). An earlier revision omitted the
    # comparison, which inverted the test and failed healthy runs.
    [[ "$bound" == 0 ]] || fail "runner port ${PULSEVM_RUNNER_PORT:-18080} is already bound — stop the stale network or set PULSEVM_RUNNER_PORT/PULSEVM_RUNNER_GATEWAY_PORT"
    # Fully detached (python double-fork + setsid): the boot supervisor must
    # neither stall this script's exit (a shell waits for its children on the
    # way out) nor die with it — after PASS the network stays up until
    # `stop`. The supervisor records its own PID for `stop`/fail cleanup.
    # A bare nohup/& background stays in this script's process group, so any
    # supervisor that reaps the group (CI cleanup, tooling, session end)
    # would SIGTERM the network with it; setsid(2) escapes the group on both
    # Linux and macOS (which ships no `setsid` binary, hence python3).
    export METALGO_EXEC_PATH="${METALGO_EXEC_PATH:-$REPO_ROOT/../metalgo-tahoe/build/metalgo}"
    export PULSEVM_MIGRATION_CHECKPOINT="$checkpoint"
    export PULSEVM_PLUGIN_DIR="$WORK_DIR/plugins"
    export PULSEVM_EC2_RUN_DIR="$WORK_DIR/five-node"
    export PULSEVM_VERIFY_FIVE_NODE=false
    (cd "$REPO_ROOT" && python3 - "$WORK_DIR/five-node.pid" "$WORK_DIR/five-node.log" <<'EOF'
import os, sys
pidfile, logfile = sys.argv[1], sys.argv[2]
if os.fork() != 0:
    sys.exit(0)
os.setsid()
if os.fork() != 0:
    os._exit(0)
open(pidfile, "w").write(str(os.getpid()) + "\n")
os.chdir(os.getcwd())
for fd in (0, 1, 2):
    try:
        os.close(fd)
    except OSError:
        pass
os.open("/dev/null", os.O_RDONLY)
os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
os.dup2(1, 2)
# PEP 446: os.open fds are non-inheritable (CLOEXEC) — without this the
# exec'd supervisor starts with std fds closed and every echo fails.
for fd in (0, 1, 2):
    os.set_inheritable(fd, True)
os.execvpe("./scripts/run-local.sh", ["./scripts/run-local.sh"], os.environ)
EOF
    ) || fail "five-node boot supervisor failed to start"
    echo "handover: building the probe-tx tool..."
    (cd "$REPO_ROOT" && cargo build --locked --release -p pulsevm_core --example make_probe_tx) \
        || fail "probe tool build failed"
    PROBE_BIN="$REPO_ROOT/target/release/examples/make_probe_tx"
    # The new network only builds on demand: empty blocks are gated, so H+1
    # needs a transaction. Submit the network's first transaction itself.
    echo "handover: waiting for the new network RPC..."
    rpc_url=""
    for _ in $(seq 1 60); do
        rpc_url="$(chain_rpc_url || true)"
        [[ -n "$rpc_url" ]] || { sleep 5; continue; }
        rpc_call "$rpc_url" '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' >/dev/null 2>&1 && break
        rpc_url=""
        sleep 5
    done
    [[ -n "$rpc_url" ]] || fail "new network RPC never came up (see $WORK_DIR/five-node.log)"
    read -r new_chain new_head new_head_id <<<"$(rpc_call "$rpc_url" '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' \
        | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]; print(r["chain_id"], r["head_block_num"], r["head_block_id"])')"
    [[ -n "${new_chain:-}" && -n "${new_head_id:-}" ]] || fail "new network getInfo failed"
    # Optional chaos: drop one validator before the first transaction, so
    # H+1 must finalize on 4/5 quorum. Off by default; the dead node is left
    # down (a restart path is future work).
    if [[ "${CHAOS_KILL_NODE:-0}" == 1 ]]; then
        victim="$(pgrep -f 'node5/configs' | head -1 || true)"
        [[ -n "$victim" ]] || victim="$(pgrep -f 'metalgo-tahoe' | head -1 || true)"
        [[ -n "$victim" ]] || fail "chaos requested but no node process found"
        kill -9 "$victim" && echo "handover: chaos: killed node pid $victim; H+1 must land on 4/5"
    fi
    echo "handover: new network at head $new_head; submitting its first transactions..."
    # Timestamp-suffixed names stay unique across reboots of one checkpoint.
    # EOS names only allow a-z, 1-5 and '.': decimal epochs contain 0 and
    # 6-9, so encode the epoch in base 5 (digits mapped to 1-5). Mod 5^10
    # keeps 10 chars, unique for ~113 days of reboots.
    dtag="d$(python3 -c "
e = int(__import__('time').time()) % 9765625
s = ''
for _ in range(10):
    s = '12345'[e % 5] + s
    e //= 5
print(s)")"
    ref_prefix="$(python3 -c "import sys; print(int.from_bytes(bytes.fromhex('$new_head_id')[8:12], 'little'))")"
    exp="$(($(date +%s) + 1800))"
    phase3='[]'
    for i in 1 2 3 4 5; do
        dname="${dtag}${i}"
        probe_tx="$("$PROBE_BIN" newaccount "$new_chain" "$PULSEVM_PRODUCER_KEY" "$new_head" "$ref_prefix" "$exp" "$dname")"
        txid="$(rpc_call "$rpc_url" "$probe_tx" \
            | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["txID"])')" \
            || fail "first-transaction submission failed"
        echo "handover: new-network tx $dname: $txid"
        phase3="$(printf '%s' "$phase3" | python3 -c "import json,sys; l=json.load(sys.stdin); l.append({\"name\": \"$dname\", \"txid\": \"$txid\"}); print(json.dumps(l))")"
    done
    # Older checkpoints predate boundary traffic: start an empty record so
    # the audit still covers phase 3.
    [[ -f "$WORK_DIR/boundary-txns.json" ]] \
        || echo '{"submit_head": 0, "phase1": [], "phase3": []}' >"$WORK_DIR/boundary-txns.json"
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["phase3"] = json.loads(sys.argv[2]); d["new_head"] = int(sys.argv[3]); json.dump(d, open(sys.argv[1], "w"), indent=1)' \
        "$WORK_DIR/boundary-txns.json" "$phase3" "$new_head"
    echo "handover: boundary phase 3 submitted; waiting for the new network to pass H..."
    wait_iters=60
    [[ "${CHAOS_KILL_NODE:-0}" == 1 ]] && wait_iters=150
    rpc_url=""
    new_head=0
    for i in $(seq 1 $wait_iters); do
        rpc_url="$(chain_rpc_url || true)"
        [[ -n "$rpc_url" ]] || { sleep 5; continue; }
        new_head="$(rpc_call "$rpc_url" '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' 2>/dev/null \
            | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["head_block_num"])' 2>/dev/null || echo 0)"
        [[ "$new_head" -gt "$H" ]] && break
        [[ $((i % 6)) == 0 ]] && echo "handover: still at $new_head, waiting for H+1 ($i/$wait_iters)..."
        sleep 5
    done
    [[ "$new_head" -gt "$H" ]] || fail "new network never passed H=$H (see $WORK_DIR/five-node.log)"
    # block_num_or_id must be a string: the endpoint rejects a bare integer
    # with "Invalid params", which would fail closed under set -e here.
    next_id="$(rpc_call "$rpc_url" '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getBlock","params":{"block_num_or_id":"'"$((H + 1))"'"}}' \
        | python3 -c 'import json,sys; b=json.load(sys.stdin)["result"]; print(b["previous"], b["block_num"])')"
    [[ "$next_id" == "$H_ID $((H + 1))" ]] || fail "continuity broken: block H+1 parent is $next_id, expected parent $H_ID"
    # State equivalence: every pre-halt traffic account must read back on
    # the new network with byte-identical authorities. Key strings differ
    # by format (EOS legacy vs PUB_K1_) but carry the same 33-byte payload,
    # so compare decoded payloads, not strings.
    echo "handover: proving migrated state equals pre-halt XPR state..."
    python3 - "$WORK_DIR/pre-halt-accounts.json" "$rpc_url" <<'PYEOF' || fail "migrated state mismatch"
import json, sys, urllib.request
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
def keybytes(s):
    if s.startswith("PUB_K1_"):
        body = s[len("PUB_K1_"):]
    elif s.startswith("EOS"):
        body = s[len("EOS"):]
    else:
        assert False, f"unexpected key format {s}"
    payload = b58decode(body)[:-4]
    assert len(payload) == 33, f"bad payload length for {s}"
    return payload.hex()
def norm_auth(a):
    return {
        "threshold": a["threshold"],
        "keys": sorted((keybytes(k["key"]), k["weight"]) for k in a.get("keys", [])),
        "accounts": sorted((x["permission"]["actor"], x["permission"]["permission"], x["weight"]) for x in a.get("accounts", [])),
        "waits": sorted((x["wait_sec"], x["weight"]) for x in a.get("waits", [])),
    }
def norm_perms(acct):
    return {p["perm_name"]: (p["parent"], norm_auth(p["required_auth"])) for p in acct["permissions"]}
def get_account(rpc, name):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "pulsevm.getAccount",
                       "params": {"account_name": name}}).encode()
    req = urllib.request.Request(rpc, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)["result"]
pre, rpc = sys.argv[1], sys.argv[2]
old = json.load(open(pre))
bad = 0
for name, old_acct in sorted(old.items()):
    try:
        new_perms = norm_perms(get_account(rpc, name))
    except Exception as e:
        print(f"  {name}: MISSING on new network ({e})")
        bad += 1
        continue
    if new_perms == norm_perms(old_acct):
        print(f"  {name}: identical")
    else:
        print(f"  {name}: MISMATCH")
        print(f"    old: {json.dumps(norm_perms(old_acct), sort_keys=True)}")
        print(f"    new: {json.dumps(new_perms, sort_keys=True)}")
        bad += 1
print(f"equivalence: {len(old) - bad}/{len(old)} accounts identical")
sys.exit(1 if bad else 0)
PYEOF
    old_chain="$(shadow_head >/dev/null 2>&1; curl --fail --silent --max-time 10 -X POST "$SHADOW_RPC/" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["chain_id"])' 2>/dev/null || echo stopped)"
    new_chain="$(rpc_call "$rpc_url" '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["chain_id"])')"
    # Boundary audit: from the customer's seat the network never stops, it
    # swaps. Every phase-1 tx must sit at or below H on the old chain, every
    # phase-3 tx strictly above H on the new chain, and no txid may appear
    # on both sides: none lost, none duplicated.
    echo "handover: auditing exactly-once across the swap..."
    python3 - "$WORK_DIR/boundary-txns.json" "$rpc_url" "$H" <<'PYEOF' || fail "boundary audit failed"
import json, sys, urllib.request
def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)
def pulse_trx_ids(rpc, num):
    body = {"jsonrpc": "2.0", "id": 1, "method": "pulsevm.getBlock",
            "params": {"block_num_or_id": str(num)}}
    block = post(rpc, body)["result"]
    ids = set()
    for t in block.get("transactions", []):
        trx = t.get("trx", t)
        tid = trx.get("id") if isinstance(trx, dict) else trx
        if isinstance(tid, str) and len(tid) == 64:
            ids.add(tid)
    return ids
rec = json.load(open(sys.argv[1]))
rpc, H = sys.argv[2], int(sys.argv[3])
phase1 = {t["txid"] for t in rec.get("phase1", [])}
phase3 = {t["txid"] for t in rec.get("phase3", [])}
old_ids = set(rec.get("old_ids", []))
new_ids = set()
head = post(rpc, {"jsonrpc": "2.0", "id": 1, "method": "pulsevm.getInfo",
                  "params": {}})["result"]["head_block_num"]
for num in range(H + 1, head + 1):
    new_ids |= pulse_trx_ids(rpc, num)
print(f"  old chain pre-halt scan: {len(old_ids)} txs; new chain blocks [{H + 1},{head}]: {len(new_ids)} txs")
bad = 0
for tid in sorted(phase1):
    if tid not in old_ids:
        print(f"  LOST pre-halt tx {tid}")
        bad += 1
for tid in sorted(phase3):
    if tid not in new_ids:
        print(f"  LOST post-halt tx {tid}")
        bad += 1
if phase1 & new_ids:
    print(f"  DUPLICATED across swap: {sorted(phase1 & new_ids)}")
    bad += 1
if phase3 & old_ids:
    print(f"  DUPLICATED across swap: {sorted(phase3 & old_ids)}")
    bad += 1
print(f"boundary: {len(phase1) + len(phase3) - bad}/{len(phase1) + len(phase3)} txs exactly-once")
sys.exit(1 if bad else 0)
PYEOF
    echo "handover: PASS: block $((H + 1)) builds on committed halt block $H_ID with identical migrated state and exactly-once boundary traffic; shadow chain $old_chain -> new chain $new_chain"
    echo "handover: new network RPC: $rpc_url (left running; run stop to tear down)"
}

cmd_stop() {
    if [[ -f "$WORK_DIR/five-node.pid" ]]; then
        kill "$(cat "$WORK_DIR/five-node.pid")" 2>/dev/null || true
        pkill -f metal-network-runner 2>/dev/null || true
    fi
    (cd "$SCRIPT_DIR" && docker compose -f compose.yaml down --volumes 2>/dev/null) || true
    # Archive instead of deleting: the workdir holds the evidence trail
    # (H, checkpoint pointer, pre-halt state) for post-mortems and resumes.
    if [[ -e "$WORK_DIR" ]]; then
        bak="$WORK_DIR.bak-$(date +%s)"
        mv "$WORK_DIR" "$bak" && echo "handover: stopped (workdir archived at $bak)"
    else
        echo "handover: stopped"
    fi
}

case "${1:-}" in
    start) cmd_start ;;
    # Resume a halted rehearsal from the checkpoint phase (H, H_ID and
    # snapshot files already in HANDOVER_WORK_DIR).
    resume-checkpoint) cmd_checkpoint ;;
    # Resume a checkpointed rehearsal from the five-node boot.
    resume-boot) cmd_boot "$(cat "${HANDOVER_WORK_DIR:-/tmp/pulsevm-handover}/checkpoint")" ;;
    stop) cmd_stop ;;
    *) echo "usage: run-handover.sh start|resume-checkpoint|resume-boot|stop" >&2
       echo "env: TERMINAL_HEIGHT (default 300, ~3 min at 0.5s blocks)," >&2
       echo "     HANDOVER_WORK_DIR, XPR_CORE_DIR, METALGO_EXEC_PATH," >&2
       echo "     LEAP_HTTP_PORT, LEAP_V1_HTTP_PORT, LEAP_V2_HTTP_PORT, SHADOW_RPC_PORT," >&2
       echo "     CHAOS_KILL_NODE=1 (drop one validator before H+1; default off)" >&2
       exit 2 ;;
esac
