#!/usr/bin/env bash
# Rehearse the two-step cutover: a three-node Leap network runs XPR under
# consensus, PulseVM shadows it block by block, the old schedule declares H
# as its last block while H is still in the future (step one, recorded
# on-chain K blocks early), the rehearsal freezes the producer exactly at H,
# the quorum confirms H with the checkpoint and the successor chain id
# (step two), and a five-node PulseVM network boots from the checkpoint and
# continues at H+1.
#
# The freeze stands in for the mainnet producer pact (BPs stop authoring at
# the agreed H; the real XPR network keeps producing, and the A-Chain simply
# ignores blocks past H). Promotion re-identifies the chain (the migration
# genesis commits to the checkpoint hash). This rehearsal validates follow,
# declaration, on-chain memo, exact freeze, confirmation, checkpoint, boot,
# parent linkage, and liveness.
set -euo pipefail
# A set -e exit otherwise leaves no trace (no fail() line, no line
# number): trap it so the next silent death names its line and command.
# -E (errtrace) extends the trap into shell functions; without it a
# failure inside confirm_attach_verify/learn_then_bind_retry would still
# die silently.
set -E
trap 'echo "handover: FATAL: exiting on error at line $LINENO: $BASH_COMMAND" >&2' ERR

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
    # The supervisor is a setsid(2) group leader, so a negative PID kills
    # exactly our tree. Never pkill by bare name: this box is shared with
    # unrelated live networks.
    if [[ -f "${WORK_DIR:-/nonexistent}/five-node.pid" ]]; then
        kill -- "-$(cat "$WORK_DIR/five-node.pid")" 2>/dev/null || true
        # The runner can escape the supervisor's process group (reparented to
        # init on some paths): reclaim exactly our runner ports, nothing
        # else. The boot gate refuses to start when our ports are held by
        # anyone else, so a holder here is ours or our stale leftover.
        for _port in "${PULSEVM_RUNNER_PORT:-18080}" "${PULSEVM_RUNNER_GATEWAY_PORT:-18081}"; do
            _victims="$(lsof -ti "tcp:${_port}" -sTCP:LISTEN 2>/dev/null || true)"
            [[ -n "$_victims" ]] && kill $_victims 2>/dev/null || true
        done
    fi
    if [[ -f "${WORK_DIR:-/nonexistent}/shadow.pid" ]]; then
        kill "$(cat "$WORK_DIR/shadow.pid")" 2>/dev/null || true
    fi
    kill_relaunched
    kill "${HEARTBEAT_PID:-}" 2>/dev/null || true
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
    (cd "$REPO_ROOT" && cargo build --locked --release --example xpr_halt_ceremony) || fail "ceremony tool build failed"
    CEREMONY_BIN="$REPO_ROOT/target/release/examples/xpr_halt_ceremony"
    [[ -x "$CEREMONY_BIN" ]] || fail "ceremony tool missing: $CEREMONY_BIN"
    (cd "$REPO_ROOT" && cargo build --locked --release -p pulsevm_core --example xpr_scan_contract_votes) || fail "scanner build failed"
    SCANNER_BIN="$REPO_ROOT/target/release/examples/xpr_scan_contract_votes"
    [[ -x "$SCANNER_BIN" ]] || fail "scanner missing: $SCANNER_BIN"
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
        (cd "$SCRIPT_DIR" && docker compose -f compose.yaml up --detach shadow) \
            || fail "shadow container failed to start"
        # Fail fast when the shadow won't stay up (e.g. a host-built binary
        # the container runtime cannot exec): otherwise the loop below spins
        # forever on a dead shadow. The Mac rehearsal uses XPR_SHADOW_NATIVE=1
        # instead; this guard protects Linux/EC2 runs.
        for _ in $(seq 1 12); do
            shadow_head >/dev/null 2>&1 && break
            shadow_cid="$(cd "$SCRIPT_DIR" && docker compose -f compose.yaml ps -q shadow)"
            if [[ -z "$shadow_cid" ]] || ! docker inspect -f '{{.State.Running}}' "$shadow_cid" 2>/dev/null | grep -q true; then
                echo "handover: shadow container died at startup; last logs:" >&2
                (cd "$SCRIPT_DIR" && docker compose -f compose.yaml logs --tail=30 shadow >&2 || true)
                fail "shadow container is not running — cannot follow XPR (on Mac hosts use XPR_SHADOW_NATIVE=1)"
            fi
            sleep 5
        done
        shadow_head >/dev/null 2>&1 || fail "shadow RPC never answered :${SHADOW_RPC_PORT:-9660}"
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
            if ! head="$(shadow_head 2>/dev/null)"; then
                echo "handover: shadow RPC lost; last logs:" >&2
                (cd "$SCRIPT_DIR" && docker compose -f compose.yaml logs --tail=30 shadow >&2 || true)
                fail "shadow died mid-follow — cannot reach $TERMINAL_HEIGHT"
            fi
            echo "handover: shadow head $head / $TERMINAL_HEIGHT"
            [[ "$head" -ge "$TERMINAL_HEIGHT" ]] && break
            sleep 5
        done
    fi
    cmd_halt
}

# Poll a Leap read until a python expression over the response JSON equals
# the wanted value (prefix the want with ! to require inequality). Effect
# waits: the chain must have advanced past our push AND included it — a bare
# head advance can win the race while our transaction still sits in the
# mempool, which would seal an empty tally or execute against missing code.
leap_wait_effect() { # $1=desc $2=path $3=body $4=py-expr $5=want
    local desc="$1" path="$2" body="$3" expr="$4" want="$5" got attempt negate=""
    if [[ "$want" == "!"* ]]; then negate=1; want="${want#!}"; fi
    for attempt in $(seq 1 60); do
        got="$(leap_post "$LEAP_API" "$path" "$body" 2>/dev/null \
            | python3 -c 'import json,sys; print('"$expr"')' 2>/dev/null || echo MISSING)"
        if [[ -n "$negate" && "$got" != "$want" && "$got" != "MISSING" ]] || [[ -z "$negate" && "$got" == "$want" ]]; then
            echo "handover: $desc ok ($got)"
            return 0
        fi
        [[ "$attempt" == 60 ]] && fail "$desc never observed (last: $got)"
        sleep 2
    done
}

# Push one transaction with fresh tapos and wait until the chain advances
# past the push head, so dependent pushes (account, then code, then init,
# then vote) cannot reorder. Prints nothing; sets LEAP_TAPOS_CHAIN/HEAD.
leap_tapos_push() { # $1=wif $2=mode rest=mode args
    local wif="$1" mode="$2"
    shift 2
    local t_chain t_head t_head_id
    read -r t_chain t_head t_head_id <<<"$(leap_chain_head "$LEAP_API")"
    LEAP_TAPOS_CHAIN="$t_chain"
    LEAP_TAPOS_HEAD="$t_head"
    local t_prefix t_exp t_ref
    t_prefix="$(python3 -c "import sys; print(int.from_bytes(bytes.fromhex('$t_head_id')[8:12], 'little'))")"
    t_exp="$(($(date +%s) + 1800))"
    t_ref="$((t_head & 0xffff))"
    leap_send "$("$PROBE_BIN" "$mode" "$t_chain" "$wif" "$t_ref" "$t_prefix" "$t_exp" "$@")" \
        || return 1
    local now
    for _ in $(seq 1 30); do
        now="$(leap_head_lib "$LEAP_API" 2>/dev/null | cut -d' ' -f1)"
        [[ "${now:-0}" -gt "$t_head" ]] && return 0
        sleep 0.5
    done
    echo "handover: push $mode never landed (head stuck at $t_head)" >&2
    return 1
}

# Fixture-only schedule seeder for the contract vehicle: the bare fixture
# chain carries no system `producers` table, so the cutover contract's init
# would freeze an empty schedule. This deploys the throwaway seeder as
# code=eosio (the only writer allowed there) and plants the single-member
# row mirroring the replayed genesis schedule (owner eosio, fixture dev
# key, weight 1.0). NEVER on mainnet: there the live schedule is real.
deploy_fixture_seeder() { # $1=dev wif
    local wif="$1"
    echo "handover: contract vehicle: planting the fixture schedule row..."
    local seed_wasm="$REPO_ROOT/contracts/cutover/seed.wasm"
    local seed_abi="$REPO_ROOT/contracts/cutover/seed.abi"
    [[ -f "$seed_wasm" && -f "$seed_abi" ]] || fail "cutover contracts not built (contracts/cutover)"
    local key33
    key33="$("$PROBE_BIN" pubkey "$wif")" || fail "dev key to pubkey failed"
    [[ "${#key33}" == 66 ]] || fail "dev pubkey is not 33 compressed bytes"
    local code_hash
    code_hash="$(leap_post "$LEAP_API" /v1/chain/get_code '{"account_name":"eosio"}' \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["code_hash"])')"
    if [[ "$code_hash" == "0000000000000000000000000000000000000000000000000000000000000000" ]]; then
        echo "handover: deploying fixture seeder as code=eosio..."
        leap_tapos_push "$wif" setcode eosio "$seed_wasm" || fail "seeder setcode failed"
        leap_tapos_push "$wif" setabi eosio "$seed_abi" || fail "seeder setabi failed"
        leap_wait_effect "seeder code on eosio" /v1/chain/get_code '{"account_name":"eosio"}' \
            'json.load(sys.stdin)["code_hash"]' '!0000000000000000000000000000000000000000000000000000000000000000'
    fi
    local rows
    rows="$(leap_post "$LEAP_API" /v1/chain/get_table_rows \
        '{"json":false,"code":"eosio","scope":"eosio","table":"producers","limit":1}' \
        | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["rows"]))')"
    if [[ "$rows" == 0 ]]; then
        local votes_hex
        votes_hex="$(python3 -c 'import struct; print(struct.pack("<d", 1.0).hex())')"
        leap_tapos_push "$wif" cseed eosio eosio eosio "$votes_hex" "$key33" 1 \
            || fail "schedule seed row failed"
    fi
    echo "handover: fixture schedule row present"
}

two_step_ceremony_and_freeze() {
    # Step one of the cutover while H is still in the future: choose H,
    # sign the declaration, record its digest on-chain, then freeze the
    # producer exactly at H. Retries (new H, new memo names) on freeze
    # overshoot; earlier rounds stay on-chain as superseded history.
    # Leaves the producer paused, H/H_ID/block-H.json/snapshot staged.
    local halt_key
    halt_key="${DEV_KEY:-${PULSEVM_PRODUCER_KEY:-5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3}}"
    PROBE_BIN="${PROBE_BIN:-$REPO_ROOT/target/release/examples/make_probe_tx}"
    CEREMONY_BIN="${CEREMONY_BIN:-$REPO_ROOT/target/release/examples/xpr_halt_ceremony}"
    SCANNER_BIN="${SCANNER_BIN:-$REPO_ROOT/target/release/examples/xpr_scan_contract_votes}"
    # Always rebuild (see the attach-stage note): stale ceremony tools
    # would sign or scan against yesterday's logic.
    (cd "$REPO_ROOT" && cargo build --locked --release -p pulsevm_core --example make_probe_tx) || fail "probe tool build failed"
    (cd "$REPO_ROOT" && cargo build --locked --release --example xpr_halt_ceremony) || fail "ceremony tool build failed"
    (cd "$REPO_ROOT" && cargo build --locked --release -p pulsevm_core --example xpr_scan_contract_votes) || fail "scanner build failed"
    # The fixture schedule is one member: eosio on the fixture genesis key.
    local roster_key
    roster_key="$(jq -er '.initial_key' "$REPO_ROOT/tools/xpr-chainbase-export/localnet/genesis.json")"
    printf '[{"producer":"eosio","key":"%s","weight":1}]' "$roster_key" >"$WORK_DIR/roster.json"
    if [[ "${CUTOVER_VEHICLE:-memo}" == "contract" ]]; then
        deploy_fixture_seeder "$halt_key"
    fi
    local producer_cid
    producer_cid="$(cd "$SCRIPT_DIR" && docker compose -f compose.yaml ps -q xpr-producer)"
    [[ -n "$producer_cid" ]] || fail "xpr-producer container not found"
    # H, DECL_DIGEST, MEMO_BLOCK, K stay global (like the legacy loop's H):
    # the shared tail below and cmd_boot read them and their files.
    local round
    round=0
    H=""
    while [[ -z "$H" ]]; do
        round="$((round + 1))"
        [[ "$round" -le 3 ]] || fail "freeze missed the declared H three times; aborting"
        local x_chain x_head
        read -r x_chain x_head _ <<<"$(leap_chain_head "$LEAP_API")"
        # The declare->memo->scan phase takes ~10-16 blocks; the lag must
        # clear it with margin or every round overshoots before freezing.
        H="$((x_head + ${CUTOVER_LAG:-30}))"
        echo "handover: cutover round $round: declaring H=$H at head $x_head..."
        if [[ "${CUTOVER_VEHICLE:-memo}" == "contract" ]]; then
            # Contract vehicle: the declaration digest comes from the frozen
            # on-chain ceremony, not from a local signing. Deploy a fresh
            # ceremony contract per round (a superseded round may have locked
            # its freeze with votes, and the contract is intentionally
            # one-shot), freeze the live schedule, cast the BP vote, and scan
            # the window into the verifier evidence fragment plus the
            # declaration the confirmation will chain.
            CONTRACT_ACCT="cutover$round"
            local cut_wasm="$REPO_ROOT/contracts/cutover/cutover.wasm"
            local cut_abi="$REPO_ROOT/contracts/cutover/cutover.abi"
            [[ -f "$cut_wasm" && -f "$cut_abi" ]] || fail "cutover contract not built (contracts/cutover)"
            leap_tapos_push "$halt_key" newaccount "$CONTRACT_ACCT" || fail "contract account failed"
            leap_wait_effect "contract account $CONTRACT_ACCT" /v1/chain/get_account \
                '{"account_name":"'"$CONTRACT_ACCT"'"}' 'json.load(sys.stdin)["account_name"]' "$CONTRACT_ACCT"
            leap_tapos_push "$halt_key" setcode "$CONTRACT_ACCT" "$cut_wasm" || fail "contract setcode failed"
            leap_tapos_push "$halt_key" setabi "$CONTRACT_ACCT" "$cut_abi" || fail "contract setabi failed"
            echo "handover: ceremony contract deployed at $CONTRACT_ACCT"
            leap_wait_effect "contract code on $CONTRACT_ACCT" /v1/chain/get_code \
                '{"account_name":"'"$CONTRACT_ACCT"'"}' 'json.load(sys.stdin)["code_hash"]' \
                '!0000000000000000000000000000000000000000000000000000000000000000'
            local init_hex
            init_hex="$(python3 -c "import struct; print((struct.pack('<I', $H) + bytes.fromhex('$x_chain')).hex())")"
            leap_tapos_push "$halt_key" raw "$CONTRACT_ACCT" init "$CONTRACT_ACCT" "$init_hex" || fail "contract init H=$H failed"
            echo "handover: schedule frozen for H=$H"
            leap_wait_effect "frozen ceremony H=$H" /v1/chain/get_table_rows \
                '{"json":true,"code":"'"$CONTRACT_ACCT"'","scope":"'"$CONTRACT_ACCT"'","table":"ceremony","limit":1}' \
                'json.load(sys.stdin)["rows"][0]["h"]' "$H"
            printf '[{"producer":"eosio","key":"%s","weight":"1"}]' "$roster_key" >"$WORK_DIR/cvote-members.json"
            leap_tapos_push "$halt_key" cvote "$CONTRACT_ACCT" "$CONTRACT_ACCT" eosio "$halt_key" "$H" "$x_chain" "$WORK_DIR/cvote-members.json" || fail "contract vote failed"
            echo "handover: vote cast, scanning the window for contract evidence..."
            leap_wait_effect "counted vote on $CONTRACT_ACCT" /v1/chain/get_table_rows \
                '{"json":true,"code":"'"$CONTRACT_ACCT"'","scope":"'"$CONTRACT_ACCT"'","table":"ceremony","limit":1}' \
                'json.load(sys.stdin)["rows"][0]["voted_weight"]' '!0'
            local scan_to scan_log
            scan_to="$(leap_chain_head "$LEAP_API" | cut -d' ' -f2)"
            scan_log="$WORK_DIR/scan-round$round.log"
            if ! "$SCANNER_BIN" --api "$LEAP_API" --contract "$CONTRACT_ACCT" --from "$x_head" --to "$scan_to" \
                --singleton-block "$scan_to" --out "$WORK_DIR/fragment.json" \
                --declare-out "$WORK_DIR/declaration.json" \
                --host-header '0.0.0.0:8888' >"$scan_log" 2>&1; then
                tail -5 "$scan_log"
                fail "vote scan failed"
            fi
            cat "$scan_log"
            DECL_DIGEST="$(python3 -c 'import json; print(json.load(open("'"$WORK_DIR/fragment.json"'"))["declaration_digest"])')"
            [[ "${#DECL_DIGEST}" == 64 ]] || fail "could not parse fragment digest"
            local vote_version
            vote_version="$(grep -o 'schedule_version=[0-9]*' "$scan_log" | cut -d= -f2)"
            [[ -n "$vote_version" ]] || fail "scanner attested no schedule version"
            echo "$vote_version" >"$WORK_DIR/schedule-version"
            echo "$CONTRACT_ACCT" >"$WORK_DIR/contract-account"
            # Quorum-completion block: the first block whose cumulative tally
            # clears strict 2/3+1. This is the declaration inclusion.
            local vote_code
            vote_code=0
            MEMO_BLOCK="$(python3 - "$WORK_DIR/fragment.json" "$WORK_DIR/declaration.json" <<'PYEOF'
import json, sys
frag = json.load(open(sys.argv[1]))
decl = json.load(open(sys.argv[2]))
weights = {m["producer"]: int(m["weight"]) for m in decl["validator_set"]}
total = sum(weights.values())
voted, completion = 0, None
for v in sorted(frag["votes"], key=lambda v: v["block"]):
    if v["producer"] not in weights:
        sys.exit(f"vote from {v['producer']} names no frozen member")
    voted += weights[v["producer"]]
    if voted * 3 > total * 2:
        completion = v["block"]
        break
if completion is None:
    sys.exit("quorum never completed in the scanned votes")
print(completion)
PYEOF
)" || vote_code=$?
            [[ "$vote_code" == 0 && -n "$MEMO_BLOCK" ]] || fail "quorum completion not found"
            K="$((H - MEMO_BLOCK))"
            if [[ "$K" -lt 1 || "$K" -gt "${CUTOVER_LAG:-30}" ]]; then
                echo "handover: round $round vote block $MEMO_BLOCK outside the window for H=$H (K=$K); superseded, retrying..."
                H=""
                continue
            fi
            echo "handover: round $round quorum completed in block $MEMO_BLOCK (K=$K); digest $DECL_DIGEST"
        else
        local decl_out
        decl_out="$("$CEREMONY_BIN" declare --height "$H" --source-chain "$x_chain" --roster "$WORK_DIR/roster.json" --key "$halt_key" --out "$WORK_DIR/declaration.json")" \
            || fail "declaration failed"
        echo "handover: $decl_out"
        DECL_DIGEST="$(printf '%s' "$decl_out" | awk '{print $2}')"
        [[ "${#DECL_DIGEST}" == 64 ]] || fail "could not parse declaration digest"
        # Memo: the declaration digest as newaccount names (hex nibbles to
        # a-p, 10 per name, round letter disambiguates retries). Recomputing
        # the digest from these on-chain accounts yields exactly DECL_DIGEST.
        local memo_names
        memo_names="$(python3 - "$DECL_DIGEST" "$round" <<'PYEOF'
import sys
alpha = "abcdefghijklmnop"
letters = "".join(alpha[int(c, 16)] for c in sys.argv[1])
letter = chr(ord("a") + int(sys.argv[2]) - 1)
chunks = [letters[i:i + 10] for i in range(0, 64, 10)]
print(" ".join("h" + letter + ch for ch in chunks))
PYEOF
)"
        local m_chain m_head m_head_id m_prefix m_exp m_ref memo_submit_head
        read -r m_chain m_head m_head_id <<<"$(leap_chain_head "$LEAP_API")"
        memo_submit_head="$m_head"
        m_prefix="$(python3 -c "import sys; print(int.from_bytes(bytes.fromhex('$m_head_id')[8:12], 'little'))")"
        m_exp="$(($(date +%s) + 1800))"
        m_ref="$((m_head & 0xffff))"
        : >"$WORK_DIR/memo-txids"
        local i mname
        i=0
        for mname in $memo_names; do
            i="$((i + 1))"
            (txid="$(leap_send "$("$PROBE_BIN" newaccount "$m_chain" "$halt_key" "$m_ref" "$m_prefix" "$m_exp" "$mname")")" \
                && echo "$i $mname $txid" >>"$WORK_DIR/memo-txids") &
        done
        wait
        # 64 hex nibbles at 10 per name: always exactly 7 memo accounts.
        # NOTE: wc pads its count with spaces, so compare numerically.
        [[ "$(wc -l <"$WORK_DIR/memo-txids" | tr -d ' ')" == 7 ]] || fail "memo submission lost transactions"
        local scan_code
        scan_code=0
        MEMO_BLOCK="$(python3 - "$WORK_DIR/memo-txids" "$LEAP_API" "$memo_submit_head" "$H" "$DECL_DIGEST" <<'PYEOF'
import json, sys, time, urllib.request
txfile, api, lo, H, decl = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
pairs = [line.split() for line in open(txfile).read().splitlines() if line.split()]
def post(path, body):
    req = urllib.request.Request(api + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Host": "0.0.0.0:8888"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)
want = {tx: (idx, name) for idx, name, tx in pairs}
found = {}
scanned = lo - 1
for _ in range(30):
    hi = post("/v1/chain/get_info", {})["head_block_num"]
    for num in range(scanned + 1, hi + 1):
        block = post("/v1/chain/get_block", {"block_num_or_id": str(num)})
        for t in block.get("transactions", []):
            trx = t.get("trx", t)
            tid = trx.get("id") if isinstance(trx, dict) else trx
            if tid in want and tid not in found:
                found[tid] = num
    scanned = max(scanned, hi)
    if len(found) == len(want):
        break
    time.sleep(2)
missing = sorted(set(want) - set(found))
if missing:
    print(f"memo txs missing: {missing}", file=sys.stderr)
    sys.exit(1)
blocks = sorted(set(found.values()))
print(f"memo chunks landed in blocks {blocks}", file=sys.stderr)
if max(blocks) >= H:
    print(f"memo missed H={H}", file=sys.stderr)
    sys.exit(2)
alpha = "abcdefghijklmnop"
ordered = sorted(pairs, key=lambda p: int(p[0]))
letters = "".join(name[2:] for _, name, _ in ordered)
if "".join(f"{alpha.index(c):x}" for c in letters) != decl:
    print("memo names do not decode to the declaration digest", file=sys.stderr)
    sys.exit(1)
print(max(blocks))
PYEOF
)" || scan_code=$?
        if [[ "$scan_code" == 2 ]]; then
            echo "handover: round $round memo missed H=$H; superseded, retrying..."
            H=""
            continue
        fi
        [[ "$scan_code" == 0 && -n "$MEMO_BLOCK" ]] || fail "memo verification failed"
        K="$((H - MEMO_BLOCK))"
        echo "handover: round $round memo sealed in block $MEMO_BLOCK (K=$K); digest re-decodes from chain"
        # Capture the memo accounts so the equivalence gate proves they
        # migrated too.
        python3 - "$LEAP_API" "$WORK_DIR/memo-accounts.json" $memo_names <<'PYEOF' || fail "memo account capture failed"
import json, sys, time, urllib.request
api, out, names = sys.argv[1], sys.argv[2], sys.argv[3:]
accts = {}
for name in names:
    for _ in range(30):
        try:
            req = urllib.request.Request(api + "/v1/chain/get_account",
                                         data=json.dumps({"account_name": name}).encode(),
                                         headers={"Content-Type": "application/json",
                                                  "Host": "0.0.0.0:8888"})
            with urllib.request.urlopen(req, timeout=15) as r:
                accts[name] = json.load(r)
            break
        except Exception:
            time.sleep(2)
    else:
        sys.exit(f"memo account {name} never appeared")
json.dump(accts, open(out, "w"), indent=1)
PYEOF
        fi # end CUTOVER_VEHICLE branch (memo accounts only exist on the memo path)
        # Snapshot while the producer still runs: create_snapshot is proven on
        # the producing node (legacy path), while a paused producer cannot
        # serve it, a data-dir copy races the paused commit, and this Leap
        # build never completes snapshots on non-producing nodes (pending
        # file written, HTTP response never sent). Poll to head==H, fire the
        # snapshot, and require the snapshotted head to BE H — anything else
        # means H+1 slipped in and the round is superseded (no pause yet, so
        # retrying is just a new H; the old declaration stays on-chain as
        # superseded history).
        echo "handover: round $round snapshotting the running producer at H=$H..."
        local snap_info snap_code
        snap_code=0
        snap_info="$(python3 - "$LEAP_API" "$H" <<'PYEOF'

import json, sys, time, urllib.request
api, H = sys.argv[1], int(sys.argv[2])
def post(path, payload):
    req = urllib.request.Request(api + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Host": "0.0.0.0:8888"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)
deadline = time.time() + 120
while True:
    h = post("/v1/chain/get_info", {})["head_block_num"]
    if h > H:
        print(f"overshot H={H}: at {h}", file=sys.stderr)
        sys.exit(2)
    if h == H:
        break
    if time.time() > deadline:
        print(f"head never reached H={H}", file=sys.stderr)
        sys.exit(1)
    time.sleep(0.01)
snap = post("/v1/producer/create_snapshot", {})
n, hid = snap.get("snapshot_name", ""), snap.get("head_block_id", "")
if not n or not hid:
    print(f"snapshot failed at H={H}: {snap}", file=sys.stderr)
    sys.exit(1)
print(f"{n} {hid}")
PYEOF
)" || snap_code=$?
        if [[ "$snap_code" == 2 ]]; then
            echo "handover: round $round snapshot missed H=$H; superseded, retrying..."
            H=""
            continue
        fi
        [[ "$snap_code" == 0 && -n "$snap_info" ]] || fail "producer snapshot failed"
        SNAP_NAME="${snap_info%% *}"
        SNAP_HID="${snap_info##* }"
        [[ -n "$SNAP_NAME" && -n "$SNAP_HID" ]] || fail "producer snapshot returned no name/id"
        echo "handover: snapshot $SNAP_NAME at $SNAP_HID"
        # Live-flip irreversibility gate: before pausing, require both
        # validators to report last_irreversible_block_num >= H. The cutoff
        # (votes, empty H) must be BFT-final on the source network, not
        # merely present at its tip — the producer is about to stop, so a
        # lagging LIB could never catch up afterwards. Fails closed.
        echo "handover: round $round waiting for validator LIB to cover H=$H..."
        local lib1 lib2 attempt
        for attempt in $(seq 1 60); do
            lib1="$(leap_head_lib "$LEAP_V1_API" 2>/dev/null | cut -d' ' -f2)"
            lib2="$(leap_head_lib "$LEAP_V2_API" 2>/dev/null | cut -d' ' -f2)"
            if [[ -n "${lib1:-}" && -n "${lib2:-}" && "$lib1" -ge "$H" && "$lib2" -ge "$H" ]]; then
                echo "handover: LIB covers H on both validators [$lib1 $lib2]"
                break
            fi
            [[ "$attempt" == 60 ]] && fail "validator LIB never reached H=$H ([${lib1:-?} ${lib2:-?}])"
            sleep 2
        done
        # Freeze: SIGSTOP-via-pause is instant. The exact-H anchor is the
        # pre-pause snapshot above (create_snapshot costs ~0.36s of the 0.5s
        # block interval, so the pause always lands a block or two past H).
        # The pause just stops the network for the static tail: record the
        # actual frozen head P, require P-H to be small (a large gap means
        # the pause mechanism itself is broken), and require every validator
        # to converge to P. All cutover proofs still reference H exactly.
        echo "handover: round $round freezing the producer (snapshot holds H=$H)..."
        local freeze_code
        freeze_code=0
        python3 - "$producer_cid" "$H" "$LEAP_API" <<'PYEOF' || freeze_code=$?
import json, subprocess, sys, time, urllib.request
cid, target, api = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def head():
    req = urllib.request.Request(api + "/v1/chain/get_info", data=b"{}",
                                 headers={"Content-Type": "application/json",
                                          "Host": "0.0.0.0:8888"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)["head_block_num"]
deadline = time.time() + 120
h = head()
while h < target:
    if time.time() > deadline:
        print(f"head never reached H={target}", file=sys.stderr)
        sys.exit(1)
    time.sleep(0.01)
    h = head()
r = subprocess.run(["docker", "pause", cid], capture_output=True, text=True)
if r.returncode != 0:
    print(f"docker pause failed: {r.stderr}", file=sys.stderr)
    sys.exit(1)
PYEOF
        [[ "$freeze_code" == 0 ]] || fail "producer freeze failed"
        # The paused producer cannot report its own head, so P comes from
        # the validators: wait until both agree, the head is stable across
        # 2s, and it sits within a few blocks past H. A large gap means the
        # pause path is broken, not merely racy.
        local v1 v2 v1_head v2_head P
        v1=""; v2=""; P=""
        for _ in $(seq 1 30); do
            v1="$(leap_head_lib "$LEAP_V1_API" 2>/dev/null || true)"
            v2="$(leap_head_lib "$LEAP_V2_API" 2>/dev/null || true)"
            v1_head="${v1%% *}"; v2_head="${v2%% *}"
            if [[ -n "$v1_head" && "$v1_head" == "$v2_head" && "$v1_head" -ge "$H" ]]; then
                sleep 2
                v1="$(leap_head_lib "$LEAP_V1_API" 2>/dev/null || true)"
                [[ "${v1%% *}" == "$v1_head" ]] && { P="$v1_head"; break; }
            fi
            sleep 1
        done
        if [[ -z "$P" || "$((P - H))" -gt 5 ]]; then
            echo "handover: round $round validators converged to [$v1] [$v2], not within 5 past H=$H; unpausing, retrying..."
            docker unpause "$producer_cid" >/dev/null 2>&1 || true
            H=""
            continue
        fi
        echo "handover: producer paused; network frozen at P=$P (snapshot holds exact H=$H)"
        echo "$P" >"$WORK_DIR/P"
        break
    done
    echo "$H" >"$WORK_DIR/H"
    echo "$MEMO_BLOCK" >"$WORK_DIR/memo-block"
    echo "$K" >"$WORK_DIR/cutover-K"
    echo "$DECL_DIGEST" >"$WORK_DIR/decl-digest"
    curl --fail --silent --max-time 15 -X POST "$LEAP_V1_API/v1/chain/get_block" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' \
        -d "{\"block_num_or_id\":\"$H\"}" >"$WORK_DIR/block-H.json" || fail "get_block H=$H failed"
    H_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$WORK_DIR/block-H.json")"
    echo "$H_ID" >"$WORK_DIR/H_ID"
    # The cutover block must be empty (no transactions, no schedule change):
    # the memo landed strictly below H, so anything in H is foreign traffic.
    python3 - "$WORK_DIR/block-H.json" <<'PYEOF' || fail "block H=$H is not an empty boundary"
import json, sys
b = json.load(open(sys.argv[1]))
sys.exit(0 if (not b.get("transactions") and not b.get("new_producers")) else 1)
PYEOF
    echo "handover: network frozen at P=$(cat "$WORK_DIR/P"), cutover H=$H id=$H_ID; memo block $MEMO_BLOCK (K=$K)"
    # The snapshot was taken pre-pause on the running producer: bind it to
    # the cutover H (same id ⇒ same deterministic state) and stage it from
    # the root-owned producer volume, the legacy pattern. Blocks H+1..P are
    # rehearsal stragglers past the declared cutoff, ignored by design.
    [[ "$SNAP_HID" == "$H_ID" ]] || fail "snapshot head $SNAP_HID != frozen H=$H $H_ID"
    docker run --rm -v pulsevm-handover_leap-data:/d:ro -v "$WORK_DIR:/out" ubuntu:24.04 \
        cp "/d/snapshots/$(basename "$SNAP_NAME")" /out/snapshot.bin \
        || fail "snapshot stage failed"
    echo "$WORK_DIR/snapshot.bin" >"$WORK_DIR/snapshot"
    echo "handover: exact-H snapshot staged: $WORK_DIR/snapshot.bin"
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
    if [[ "${TWO_STEP_CUTOVER:-1}" == "1" ]]; then
        # Two-step cutover: declare H in advance, memo it on-chain, snapshot
        # the running producer at H, then freeze the network. (The snapshot
        # must be taken while the producer runs: a paused producer cannot
        # serve create_snapshot, and non-producing nodes never complete it.)
        # The legacy snapshot loop below stays for TWO_STEP_CUTOVER=0
        # comparison runs.
        two_step_ceremony_and_freeze
    fi
    # TWO_STEP_CUTOVER=0 is retired: the restore gate requires the two-step
    # pair (declaration + confirmation + on-chain ceremony), and a legacy
    # single-step manifest no longer boots. Fail fast instead of running a
    # ceremony the gate will reject.
    if [[ "${TWO_STEP_CUTOVER:-1}" == "0" ]]; then
        fail "TWO_STEP_CUTOVER=0 is retired: the restore gate requires the two-step cutover pair; run without it (default)"
    # Legacy acquisition below is unreachable; kept for archaeology.
    # (Kept at cmd_halt indent: this whole block is the legacy path.)
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
    fi # end legacy acquisition; the shared tail below runs in both modes
    # Shared tail: stop the network, prove the freeze, let the shadow absorb
    # H, checkpoint. H/H_ID/block-H.json/snapshot are staged above.
    # Full network halt: stop the producer and both validators. The XPR
    # chain must freeze: no new blocks may appear in the shared block log
    # after the stop. A two-step freeze leaves the producer paused: unpause
    # first (the snapshot is staged, stragglers are ignored by design).
    docker unpause "$(cd "$SCRIPT_DIR" && docker compose -f compose.yaml ps -q xpr-producer)" >/dev/null 2>&1 || true
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
    # Id-exact absorption: height is not enough — the shadow must hold the
    # same terminal block id the snapshot binds, or the replay diverged and
    # the checkpoint would seal a foreign history.
    shadow_resp="$(curl --fail --silent --max-time 15 -X POST "$SHADOW_RPC/" \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getBlock","params":{"block_num_or_id":"'"$H"'"}}')" \
        || fail "shadow block H=$H unreadable"
    shadow_id="$(printf '%s' "$shadow_resp" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["id"])')" \
        || fail "shadow getBlock H=$H failed: $shadow_resp"
    [[ "$shadow_id" == "$H_ID" ]] || fail "shadow absorbed a different H=$H (id $shadow_id != $H_ID)"
    echo "handover: shadow absorbed exact H=$H id=$H_ID (shadow $shadow_h); checkpointing..."
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

# Confirm the frozen declaration against the terminal block, attach the
# pair to the manifest, verify offline, and write the flip-gate marker.
# Factored (not inline) because the rehearsal may run it twice: once with
# the derived platform id, and again with the id learned from the first
# boot when the runner assigns chain ids non-deterministically
# (see learn_then_bind_retry below).
confirm_attach_verify() { # $1=platform-chain-id
    local platform_chain="$1"
    local confirm_out CONF_DIGEST NEW_CHAIN h_version vote_version
    confirm_out="$("$CEREMONY_BIN" confirm --declaration "$WORK_DIR/declaration.json" --height "$H" --block-id "$H_ID" --checkpoint "$CHECKPOINT_SHA256" --genesis "$WORK_DIR/migration.genesis.json" --platform-chain-id "$platform_chain" --key "$halt_key" --out "$WORK_DIR/confirmation.json")" \
        || fail "confirmation failed"
    echo "handover: $confirm_out"
    CONF_DIGEST="$(printf '%s' "$confirm_out" | awk '{print $2}')"
    NEW_CHAIN="$(printf '%s' "$confirm_out" | awk '{for (i=1;i<=NF;i++) if ($i=="new-chain") print $(i+1)}')"
    [[ "${#CONF_DIGEST}" == 64 && "${#NEW_CHAIN}" == 64 ]] || fail "could not parse confirmation"
    echo "$CONF_DIGEST" >"$WORK_DIR/conf-digest"
    echo "$NEW_CHAIN" >"$WORK_DIR/new-chain"
    attach_args=(
        --declaration "$WORK_DIR/declaration.json" --confirmation "$WORK_DIR/confirmation.json"
        --declaration-inclusion "$(cat "$WORK_DIR/memo-block")"
        --max-declaration-lag "${CUTOVER_LAG:-30}"
        --max-confirmation-lag "${CONFIRM_LAG:-120}"
    )
    if [[ "${CUTOVER_VEHICLE:-memo}" == "contract" ]]; then
        h_version="$(python3 -c 'import json; print(json.load(open("'"$WORK_DIR/block-H.json"'"))["schedule_version"])')" \
            || fail "could not read H schedule version from block-H.json"
        vote_version="$(cat "$WORK_DIR/schedule-version")" \
            || fail "could not read frozen schedule version"
        [[ "$h_version" == "$vote_version" ]] \
            || fail "schedule rotated between the last vote (version $vote_version) and H (version $h_version)"
        echo "handover: schedule version $h_version unanimous across votes and H"
        attach_args+=(--contract-ceremony "$WORK_DIR/fragment.json" --schedule-version "$h_version")
    fi
    "$ATTACH_BIN" \
        "$manifest" "$WORK_DIR/block-H.json" "$manifest.attached" \
        "${attach_args[@]}" \
        || fail "source block attach failed (H must be an empty block)"
    mv "$manifest.attached" "$manifest"
    "$VERIFY_BIN" "$manifest" "$export_dir/migration.snapshot" --genesis "$WORK_DIR/migration.genesis.json" --platform-chain-id "$platform_chain" \
        || fail "offline pair verification failed"
    printf '%s %s %s %s\n' \
        "$(sha256sum "$manifest" | awk '{print $1}')" \
        "$CHECKPOINT_SHA256" \
        "$CONF_DIGEST" \
        "$NEW_CHAIN" >"$WORK_DIR/verification-pass" \
        || fail "verification marker write failed"
    echo "handover: two-step pair attached and verified: declaration $(cat "$WORK_DIR/decl-digest") -> confirmation $CONF_DIGEST on $NEW_CHAIN"
}

# The runner assigns chain ids non-deterministically, but the confirmation
# must bind the boot's actual id or the restore gate refuses (fail closed).
# Production sets PULSEVM_PLATFORM_CHAIN_ID from the launcher (known at
# T-14); the rehearsal learns it instead: scrape the id the first boot
# refused, re-run the ceremony against it, and restart the five nodes in
# place on the same network dir (the id is stable per network, so the
# relaunched nodes pick up the corrected manifest). Exactly one retry;
# a second refusal is a real failure, not a staler id.
learn_then_bind_retry() {
    [[ -z "${PULSEVM_PLATFORM_CHAIN_ID:-}" ]] \
        || fail "explicit PULSEVM_PLATFORM_CHAIN_ID mismatches the boot id: fix the launcher id, no auto-retry on an operator-provided value"
    # confirm_attach_verify runs in cmd_boot's scope, which lacks the
    # confirm-time locals: rebuild exactly the same values here.
    export_dir="$(dirname "${checkpoint}.manifest.json")"
    CHECKPOINT_SHA256="$(jq -er '.checkpoint_sha256' "${checkpoint}.manifest.json")"
    halt_key="${DEV_KEY:-${PULSEVM_PRODUCER_KEY:-5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3}}"
    CEREMONY_BIN="${CEREMONY_BIN:-$REPO_ROOT/target/release/examples/xpr_halt_ceremony}"
    ATTACH_BIN="$REPO_ROOT/target/release/examples/xpr_attach_source_block"
    VERIFY_BIN="${VERIFY_BIN:-$REPO_ROOT/target/release/examples/xpr_verify_manifest}"
    manifest="${checkpoint}.manifest.json"
    local netdir actual
    # Newest network dir wins: the retry runs minutes after boot, so the
    # current boot's dir is always the freshest. Portable across BSD/GNU
    # (no find -newermt, no stat flavors): plain -nt comparison only.
    netdir=""
    for cand in "${TMPDIR:-/tmp}"/network-runner-root-data/network_* /tmp/network-runner-root-data/network_*; do
        [[ -d "$cand" ]] || continue
        if [[ -z "$netdir" || "$cand" -nt "$netdir" ]]; then netdir="$cand"; fi
    done
    [[ -n "$netdir" ]] || fail "learn-then-bind: no five-node network dir found to learn the chain id from"
    actual="$(grep -rhoE 'error creating chain \{"subnetID": "[A-Za-z0-9]+", "chainID": "[A-Za-z0-9]+"' "$netdir"/node*/logs/main.log 2>/dev/null | head -1 | grep -oE 'chainID": "[A-Za-z0-9]+"' | cut -d'"' -f3 || true)"
    [[ -n "$actual" ]] || fail "learn-then-bind: no refused chain id in the node logs"
    grep -rq "halt confirmation platform chain id does not match" "$netdir"/node*/logs/main.log 2>/dev/null \
        || fail "learn-then-bind: nodes refuse for another reason, see $netdir/node*/logs/main.log"
    echo "handover: learn-then-bind: first boot runs as $actual; re-running the ceremony against it..."
    confirm_attach_verify "$actual"
    restart_five_nodes "$netdir"
}

# Restart the five nodes of one network dir in place (same configs, same
# chain id) after the manifest was corrected. Records PIDs so stop/fail
# cleanup reclaims exactly these processes too.
restart_five_nodes() { # $1=network dir
    local netdir="$1" n cfg pids pid cmdline
    pids=""
    for n in 1 2 3 4 5; do
        cfg="$netdir/node$n/configs/config.json"
        [[ -f "$cfg" ]] || fail "learn-then-bind: missing $cfg"
    done
    # Capture full command lines before killing: relaunch is byte-identical.
    # Indexed arrays only (macOS ships bash 3.2: no associative arrays),
    # and plain `&` children of this script (macOS ships no setsid
    # binary): fail()/stop reclaim them via five-node.relaunched.
    # Match on the network dir BASENAME: ps shows the path as invoked,
    # which may differ by symlink prefix (/var vs /private/var).
    NETBASE="$(basename "$netdir")"
    CMDS_1=""; CMDS_2=""; CMDS_3=""; CMDS_4=""; CMDS_5=""
    for n in 1 2 3 4 5; do
        # The supervisor may be restarting a failed node exactly as we
        # look: retry the capture instead of dying on a restart gap.
        cmdline=""
        for _ in $(seq 1 6); do
            cmdline="$(ps -eo pid,args | grep "[m]etalgo.*$NETBASE/node$n/configs" | head -1 | sed -E 's/^ *[0-9]+ //' || true)"
            [[ -n "$cmdline" ]] && break
            sleep 5
        done
        [[ -n "$cmdline" ]] || fail "learn-then-bind: node$n process not found after retries"
        eval "CMDS_$n=\"\$cmdline\""
        pids="$pids $(ps -eo pid,args | grep "[m]etalgo.*$NETBASE/node$n/configs" | head -1 | awk '{print $1}' || true)"
    done
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    for _ in $(seq 1 30); do
        alive=""
        # shellcheck disable=SC2086
        for pid in $pids; do kill -0 "$pid" 2>/dev/null && alive="$alive $pid"; done
        [[ -z "$alive" ]] && break
        sleep 2
    done
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
    : >"$WORK_DIR/five-node.relaunched"
    for n in 1 2 3 4 5; do
        eval "cmdline=\"\$CMDS_$n\""
        bash -c "$cmdline" >>"$WORK_DIR/node-restart-$n.log" 2>&1 &
        echo $! >>"$WORK_DIR/five-node.relaunched"
    done
    echo "handover: five nodes relaunched in place on the corrected manifest"
}

# Reclaim processes relaunched outside the supervisor group (see
# restart_five_nodes). Called from fail() and cmd_stop().
kill_relaunched() {
    if [[ -f "${WORK_DIR:-/nonexistent}/five-node.relaunched" ]]; then
        # shellcheck disable=SC2086
        kill $(cat "$WORK_DIR/five-node.relaunched") 2>/dev/null || true
    fi
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
    # Fixture dev key doubles as the old schedule key (rehearsal only).
    halt_key="${DEV_KEY:-${PULSEVM_PRODUCER_KEY:-5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3}}"
    if [[ "${TWO_STEP_CUTOVER:-1}" == "1" ]]; then
        # Step two of the cutover: confirm H with the checkpoint and the
        # successor chain id, attach the pair, and verify offline before any
        # node boots. The migration genesis mirrors run-local.sh's recipe
        # (base + checkpoint binding + fixture key); its derived successor
        # id is what the confirmation chains (new_chain), while the
        # platform id it binds is the launcher's id (see PLATFORM_CHAIN).
        # On the memo path the fixture chain
        # carries no producers table, so the state cross-check logs its skip
        # exactly as designed for table-less fixtures; on the contract path
        # the seeded schedule row is exported with the checkpoint, so the
        # light-client set-equality check runs and must pass.
        CEREMONY_BIN="${CEREMONY_BIN:-$REPO_ROOT/target/release/examples/xpr_halt_ceremony}"
        ATTACH_BIN="$REPO_ROOT/target/release/examples/xpr_attach_source_block"
        VERIFY_BIN="$REPO_ROOT/target/release/examples/xpr_verify_manifest"
        # Always rebuild: a skipped build silently runs yesterday's tools
        # against today's manifest, and a rehearsal that verifies with a
        # stale verifier proves nothing (this exact staleness once failed
        # the offline check on a weight encoding the code already handled).
        # Cargo no-ops in seconds when nothing changed.
        (cd "$REPO_ROOT" && cargo build --locked --release --example xpr_halt_ceremony) || fail "ceremony tool build failed"
        (cd "$REPO_ROOT" && cargo build --locked --release --example xpr_attach_source_block) || fail "attach tool build failed"
        (cd "$REPO_ROOT" && cargo build --locked --release -p pulsevm_database --example xpr_verify_manifest) || fail "verifier build failed"
        H="$(cat "$WORK_DIR/H")"
        H_ID="$(cat "$WORK_DIR/H_ID")"
        GENESIS_BASE="${PULSEVM_GENESIS_PATH:-$REPO_ROOT/genesis.json}"
        GENESIS_KEY="${PULSEVM_GENESIS_INITIAL_KEY:-$(jq -er '.initial_key' "$REPO_ROOT/tools/xpr-chainbase-export/localnet/genesis.json")}"
        CHECKPOINT_SHA256="$(jq -er '.checkpoint_sha256' "$manifest")"
        jq --arg checkpoint_sha256 "$CHECKPOINT_SHA256" \
            --arg initial_key "$GENESIS_KEY" \
            '. + {migration_checkpoint_sha256: $checkpoint_sha256, initial_key: $initial_key}' \
            "$GENESIS_BASE" >"$WORK_DIR/migration.genesis.json" || fail "migration genesis build failed"
        # Platform id the boot will run under: the confirmation binds
        # exactly this id (hex or the base58 log rendering), and the restore
        # gate fails closed on any other. Set PULSEVM_PLATFORM_CHAIN_ID from
        # the launcher when it is known in advance (production: the
        # create-chain id, published by T-14). A local runner assigns the id
        # at boot from the migration genesis, so the rehearsal learns it
        # from a first boot's log and re-runs confirm with it: defaulting to
        # the derived id only works when the boot is configured with the
        # derived id, which the runner is not.
        PLATFORM_CHAIN="${PULSEVM_PLATFORM_CHAIN_ID:-$("$CEREMONY_BIN" chain-id --genesis "$WORK_DIR/migration.genesis.json")}" \
            || fail "platform chain id derivation failed"
        confirm_attach_verify "$PLATFORM_CHAIN"
    elif [[ "${HALT_V2:-0}" == "1" ]]; then
        # Retired: the restore gate requires the two-step pair, so a
        # single-step commitment manifest no longer boots.
        fail "HALT_V2=1 is retired: the restore gate requires the two-step cutover pair"
        (cd "$REPO_ROOT" && cargo build --locked --release --example xpr_attach_source_block) \
            || fail "attach tool build failed"
        roster_key="$(jq -er '.initial_key' "$REPO_ROOT/tools/xpr-chainbase-export/localnet/genesis.json")"
        printf '[{"producer":"eosio","key":"%s","weight":1}]' "$roster_key" >"$WORK_DIR/roster.json"
        "$REPO_ROOT/target/release/examples/xpr_attach_source_block" \
            "$manifest" "$WORK_DIR/block-H.json" "$manifest.attached" \
            --halt-key-v2 "$halt_key" --halt-roster "$WORK_DIR/roster.json" \
            || fail "source block attach failed (H must be an empty block)"
        mv "$manifest.attached" "$manifest"
        echo "handover: halt commitment signed over H=$H"
    else
        (cd "$REPO_ROOT" && cargo build --locked --release --example xpr_attach_source_block) \
            || fail "attach tool build failed"
        # Retired: a roster-less v1 commitment no longer boots. This else
        # branch is unreachable; the two-step pair above is the only path.
        fail "legacy v1 halt commitment is retired: the restore gate requires the two-step cutover pair"
        "$REPO_ROOT/target/release/examples/xpr_attach_source_block" \
            "$manifest" "$WORK_DIR/block-H.json" "$manifest.attached" \
            --halt-key "$halt_key" \
            || fail "source block attach failed (H must be an empty block)"
        mv "$manifest.attached" "$manifest"
        echo "handover: halt commitment signed over H=$H"
    fi
    echo "$export_dir/migration.snapshot" >"$WORK_DIR/checkpoint"
    echo "handover: checkpoint ready: $export_dir/migration.snapshot"
    cmd_boot "$export_dir/migration.snapshot"
}

cmd_boot() {
    checkpoint="${1:?checkpoint required}"
    H="$(cat "$WORK_DIR/H")"
    H_ID="$(cat "$WORK_DIR/H_ID")"
    if [[ "${TWO_STEP_CUTOVER:-1}" == "1" ]]; then
        # Explicit flip gate: tip == H AND the confirmation finalized AND the
        # manifest still binds that tip — the boot refuses to proceed unless
        # the offline verifier passed on this exact manifest, checkpoint,
        # confirmation, and successor chain. The staged block is re-read
        # here (not trusted from an earlier shell variable) so a swapped or
        # truncated workdir fails instead of booting the wrong history.
        marker="$WORK_DIR/verification-pass"
        [[ -f "$marker" ]] || fail "refusing to boot: no verification-pass marker (confirmation not finalized)"
        manifest="${checkpoint}.manifest.json"
        expected="$(sha256sum "$manifest" | awk '{print $1}') $(jq -er '.checkpoint_sha256' "$manifest") $(cat "$WORK_DIR/conf-digest") $(cat "$WORK_DIR/new-chain")"
        [[ "$(cat "$marker")" == "$expected" ]] || fail "refusing to boot: verification-pass marker does not match this checkpoint/manifest"
        staged_id="$(python3 -c 'import json; print(json.load(open("'"$WORK_DIR/block-H.json"'"))["id"])')"
        [[ "$staged_id" == "$H_ID" ]] || fail "refusing to boot: staged block id $staged_id != frozen H=$H $H_ID"
        manifest_tip="$(jq -er '.source_block_id' "$manifest")"
        [[ "$manifest_tip" == "$H_ID" ]] || fail "refusing to boot: manifest tip $manifest_tip != frozen H=$H $H_ID"
        echo "handover: flip gate open: tip H=$H id=$H_ID plus verified confirmation $(cat "$WORK_DIR/conf-digest")"
    fi
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
    export PULSEVM_RUNNER_START_EXTRA_ARGS="--dynamic-ports --request-timeout ${PULSEVM_RUNNER_REQUEST_TIMEOUT:-30m}"
    # 30m, not 10m: a loaded box (or a slow plugin exec) can push a
    # five-node start past 10 minutes, and a request timeout mid-start
    # tears the half-built network down with only "closed server" in the
    # log. Override down, never below the time a healthy start needs.
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
    # Heartbeat: proves the harness itself is alive during the long silent
    # waits. If the log stops advancing with no FATAL line, the shell was
    # killed externally — note the last heartbeat when reporting.
    ( while true; do sleep 60; echo "handover: heartbeat $(date +%H:%M:%S) (cmd_boot rpc wait)"; done & )
    HEARTBEAT_PID=$!
    rpc_url=""
    for _wait_iter in $(seq 1 60); do
        rpc_url="$(chain_rpc_url || true)"
        [[ -n "$rpc_url" ]] || { sleep 5; continue; }
        rpc_call "$rpc_url" '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' >/dev/null 2>&1 && break
        rpc_url=""
        [[ $((_wait_iter % 12)) == 0 ]] && echo "handover: still no new-network RPC ($_wait_iter/60)..."
        sleep 5
    done
    if [[ -z "$rpc_url" ]]; then
        # First boot refused at the restore gate almost surely means the
        # confirmation binds the wrong platform id: the runner assigns
        # chain ids non-deterministically and the ceremony confirmed the
        # derived one. Learn the boot's actual id, re-run the ceremony
        # against it, and restart the nodes in place — exactly once.
        # Anything else (or a second refusal) fails below as before.
        learn_then_bind_retry
        rpc_url=""
        for _wait_iter in $(seq 1 60); do
            rpc_url="$(chain_rpc_url || true)"
            [[ -n "$rpc_url" ]] || { sleep 5; continue; }
            rpc_call "$rpc_url" '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' >/dev/null 2>&1 && break
            rpc_url=""
            [[ $((_wait_iter % 12)) == 0 ]] && echo "handover: still no new-network RPC after rebind ($_wait_iter/60)..."
            sleep 5
        done
    fi
    [[ -n "$rpc_url" ]] || fail "new network RPC never came up (see $WORK_DIR/five-node.log)"
    kill "$HEARTBEAT_PID" 2>/dev/null || true
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
import json, os, sys, urllib.request
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
# The declaration memo accounts are pre-cutover state too: prove they
# migrated alongside the pre-halt traffic (absent on legacy runs).
memo_path = os.path.join(os.path.dirname(pre), "memo-accounts.json")
if os.path.exists(memo_path):
    old.update(json.load(open(memo_path)))
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
    if [[ "${TWO_STEP_CUTOVER:-1}" == "1" ]]; then
        MEMO_BLOCK="$(cat "$WORK_DIR/memo-block" 2>/dev/null || echo ?)"
        CUTOVER_K="$(cat "$WORK_DIR/cutover-K" 2>/dev/null || echo ?)"
        DECL_DIGEST="$(cat "$WORK_DIR/decl-digest" 2>/dev/null || echo ?)"
        CONF_DIGEST="$(cat "$WORK_DIR/conf-digest" 2>/dev/null || echo ?)"
        if [[ "${CUTOVER_VEHICLE:-memo}" == "contract" ]]; then
            CONTRACT_ACCT="$(cat "$WORK_DIR/contract-account" 2>/dev/null || echo ?)"
            SCHED_VERSION="$(cat "$WORK_DIR/schedule-version" 2>/dev/null || echo ?)"
            echo "handover: PASS: two-step contract cutover declared H=$H at vote block $MEMO_BLOCK (K=$CUTOVER_K, contract $CONTRACT_ACCT, schedule version $SCHED_VERSION, declaration $DECL_DIGEST), confirmed $CONF_DIGEST binding checkpoint and new chain; block $((H + 1)) builds on H=$H_ID with identical migrated state and exactly-once boundary traffic; shadow chain $old_chain -> new chain $new_chain"
        else
            echo "handover: PASS: two-step cutover declared H=$H at memo block $MEMO_BLOCK (K=$CUTOVER_K, declaration $DECL_DIGEST), confirmed $CONF_DIGEST binding checkpoint and new chain; block $((H + 1)) builds on H=$H_ID with identical migrated state and exactly-once boundary traffic; shadow chain $old_chain -> new chain $new_chain"
        fi
    else
        echo "handover: PASS: block $((H + 1)) builds on committed halt block $H_ID with identical migrated state and exactly-once boundary traffic; shadow chain $old_chain -> new chain $new_chain"
    fi
    echo "handover: new network RPC: $rpc_url (left running; run stop to tear down)"
}

cmd_stop() {
    if [[ -f "$WORK_DIR/five-node.pid" ]]; then
        # Setsid group kill: exactly our supervisor tree, never a foreign
        # network sharing this host (see fail() above). The runner can
        # escape the group (reparented to init), so also reclaim exactly
        # our runner ports — the boot gate guarantees a holder is ours.
        kill -- "-$(cat "$WORK_DIR/five-node.pid")" 2>/dev/null || true
        for _port in "${PULSEVM_RUNNER_PORT:-18080}" "${PULSEVM_RUNNER_GATEWAY_PORT:-18081}"; do
            _victims="$(lsof -ti "tcp:${_port}" -sTCP:LISTEN 2>/dev/null || true)"
            [[ -n "$_victims" ]] && kill $_victims 2>/dev/null || true
        done
    fi
    # Nodes relaunched outside the supervisor group (learn-then-bind
    # retry) are not covered by the group kill above: reclaim exactly
    # those PIDs too.
    kill_relaunched
    docker rm -f pulsevm-handover-snapshotter 2>/dev/null || true
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
       echo "     TWO_STEP_CUTOVER must stay 1 (legacy 0 is retired: the restore" >&2
       echo "       gate requires the two-step cutover pair)," >&2
       echo "     CUTOVER_LAG (blocks between declaration and H; default 30)," >&2
       echo "     CONFIRM_LAG (confirmation deadline past H in blocks; default 120)," >&2
       echo "     CUTOVER_VEHICLE=contract (on-chain cutover contract instead of memo" >&2
       echo "       accounts for the step-one declaration; default memo)," >&2
       echo "     CHAOS_KILL_NODE=1 (drop one validator before H+1; default off)" >&2
       exit 2 ;;
esac
