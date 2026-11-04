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
# NOTE: with `set -E` this fires even for failures inside guarded contexts
# (`||`, `if` conditions) where the shell intentionally continues — most
# visibly a single failed getInfo poll. So this line alone never proves the
# run died: a real abort always pairs it with the failing command's own
# error or a `handover: ...` fail line. The orphan heartbeat (now
# self-exiting) used to make this ambiguous; it no longer does.
trap 'echo "handover: command failed at line $LINENO: $BASH_COMMAND" >&2' ERR

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
export HANDOVER_WORK_DIR="$WORK_DIR"
export PULSEVM_REPLAY_BIN="${PULSEVM_REPLAY_BIN:-$REPO_ROOT/target/release/examples/xpr_blocklog_replay}"
# Host Rust toolchain for the checkpoint importer and the replay build.
export PATH="$HOME/.cargo/bin:$PATH"

fail() {
    # FATAL here means the run is aborting (exit 1 below). The ERR trap
    # deliberately does not use the word: it also fires for guarded,
    # non-fatal failures.
    echo "handover: FATAL: $*" >&2
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

# ---- Multi-key mode (HANDOVER_PRODUCERS=4) ----------------------------------
# The default rehearsal runs one producer on one key, so the strict 2/3+1
# roster quorum, distinct per-member keys, and a schedule with more than one
# member are never exercised live. In this mode the genesis producer hands the
# chain to four producers (bpatest..bpdtest) with four distinct keys through
# eosio.bios setprods, exactly as a real chain installs a schedule; the
# ceremony then signs with HANDOVER_SIGNERS (default 3, the minimum strict
# 2/3+1 quorum of 4) of those keys and the restore gate verifies them against
# the header-state schedule. Needs the eosio.bios build (BIOS_WASM/BIOS_ABI).
MK_SUFFIXES="a b c d"
multikey_enabled() { [[ "${HANDOVER_PRODUCERS:-1}" == "4" ]]; }
multikey_port() { # $1=suffix
    case "$1" in a) echo "${BP_A_HTTP_PORT:-18890}";; b) echo "${BP_B_HTTP_PORT:-18891}";;
        c) echo "${BP_C_HTTP_PORT:-18892}";; d) echo "${BP_D_HTTP_PORT:-18893}";; esac
}
# One line per member in $WORK_DIR/bp-keys.txt: name wif pub-hex eos-key.
multikey_prepare() {
    [[ "${CUTOVER_VEHICLE:-memo}" == "memo" ]] || fail "HANDOVER_PRODUCERS=4 supports the memo vehicle only"
    local sfx wif pubhex eos name
    : >"$WORK_DIR/bp-keys.txt"
    for sfx in $MK_SUFFIXES; do
        read -r wif _ <<<"$("$PROBE_BIN" newkey)"
        pubhex="$("$PROBE_BIN" pubkey "$wif")"
        eos="$(python3 -I - "$pubhex" <<'PYEOF'
import hashlib, sys
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
raw = bytes.fromhex(sys.argv[1])
h = hashlib.new("ripemd160"); h.update(raw)
n = int.from_bytes(raw + h.digest()[:4], "big")
out = ""
while n:
    n, r = divmod(n, 58)
    out = ALPHABET[r] + out
print("EOS" + out)
PYEOF
)" || fail "schedule key encoding failed"
        name="bp${sfx}test"
        echo "$name $wif $pubhex $eos" >>"$WORK_DIR/bp-keys.txt"
        {
            echo "plugin = eosio::chain_api_plugin"
            echo "plugin = eosio::net_plugin"
            echo "plugin = eosio::producer_plugin"
            echo "plugin = eosio::producer_api_plugin"
            echo "http-server-address = 0.0.0.0:8888"
            echo "p2p-listen-endpoint = 0.0.0.0:9876"
            echo "p2p-peer-address = xpr-producer:9876"
            echo "access-control-allow-origin = *"
            echo "verbose-http-errors = true"
            echo "resource-monitor-not-shutdown-on-threshold-exceeded = true"
            echo "producer-name = $name"
            echo "signature-provider = $eos=KEY:$wif"
        } >"$WORK_DIR/bp-$sfx.ini"
    done
    chmod 600 "$WORK_DIR/bp-keys.txt" "$WORK_DIR"/bp-?.ini
}
# Comma-joined container ids of the four producers.
multikey_cids() {
    local sfx cid out=""
    for sfx in $MK_SUFFIXES; do
        cid="$(cd "$SCRIPT_DIR" && docker compose -f compose.yaml ps -q "xpr-bp-$sfx")"
        [[ -n "$cid" ]] || fail "xpr-bp-$sfx container not found"
        out="${out:+$out,}$cid"
    done
    printf '%s' "$out"
}
# Roster the ceremony declares: every member, unit weight, schedule key.
multikey_write_roster() { # $1=out
    python3 -I - "$WORK_DIR/bp-keys.txt" "$1" <<'PYEOF'
import json, sys
rows = [l.split() for l in open(sys.argv[1]) if l.strip()]
json.dump([{"producer": n, "key": eos, "weight": 1} for n, _w, _p, eos in rows], open(sys.argv[2], "w"))
PYEOF
}
# Signing keys for declare/confirm into CEREMONY_KEY_ARGS: the single fixture
# key by default, the first HANDOVER_SIGNERS member keys in multi-key mode.
ceremony_key_args() { # $1=single-mode wif
    CEREMONY_KEY_ARGS=(--key "$1")
    multikey_enabled || return 0
    local want="${HANDOVER_SIGNERS:-3}" got=0 name wif _rest
    CEREMONY_KEY_ARGS=()
    while read -r name wif _rest; do
        [[ -n "$name" && "$got" -lt "$want" ]] || continue
        CEREMONY_KEY_ARGS+=(--key "$wif")
        got=$((got + 1))
    done <"$WORK_DIR/bp-keys.txt"
    [[ "$got" == "$want" ]] || fail "only $got member keys available for $want signers"
}
multikey_install_schedule() {
    local dev_key="${PULSEVM_PRODUCER_KEY:-5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3}"
    local bios_wasm="${BIOS_WASM:-$REPO_ROOT/../proton.contracts/build/contracts/eosio.bios/eosio.bios.wasm}"
    local bios_abi="${BIOS_ABI:-$REPO_ROOT/../proton.contracts/build/contracts/eosio.bios/eosio.bios.abi}"
    local boot_wasm="$REPO_ROOT/contracts/cutover/boot.wasm" boot_abi="$REPO_ROOT/contracts/cutover/boot.abi"
    [[ -f "$bios_wasm" && -f "$bios_abi" ]] || fail "eosio.bios build not found (set BIOS_WASM / BIOS_ABI)"
    [[ -f "$boot_wasm" && -f "$boot_abi" ]] || fail "boot contract not built (contracts/cutover/build.sh)"
    multikey_prepare
    echo "handover: multi-key mode: starting four producers with distinct keys..."
    (cd "$SCRIPT_DIR" && docker compose -f compose.yaml up --detach xpr-bp-a xpr-bp-b xpr-bp-c xpr-bp-d) \
        || fail "producer containers failed to start"
    local sfx
    for sfx in $MK_SUFFIXES; do
        for _ in $(seq 1 90); do leap_node_info "http://127.0.0.1:$(multikey_port "$sfx")" >/dev/null 2>&1 && break; sleep 1; done
        leap_node_info "http://127.0.0.1:$(multikey_port "$sfx")" >/dev/null || fail "producer $sfx did not become ready"
    done
    # WTMSIG_BLOCK_SIGNATURES gates the bios's set_proposed_producers_ex.
    # A fresh chain has only PREACTIVATE_FEATURE (scheduled through the
    # producer API); the rest must be preactivated by a privileged contract.
    local preact wtmsig
    feature_digest() { # $1=name
        leap_post "$LEAP_API" /v1/producer/get_supported_protocol_features '{}' | python3 -I -c '
import json, sys
for f in json.load(sys.stdin):
    if f["specification"][0]["value"] == sys.argv[1]:
        print(f["feature_digest"]); break
else:
    sys.exit(1)' "$1"
    }
    wait_feature() { # $1=name $2=digest
        for _ in $(seq 1 60); do
            leap_post "$LEAP_API" /v1/chain/get_activated_protocol_features '{"limit":100}' \
                | python3 -I -c 'import sys; sys.exit(0 if sys.argv[1] in sys.stdin.read() else 1)' "$2" && return 0
            sleep 1
        done
        fail "feature $1 never activated"
    }
    preact="$(feature_digest PREACTIVATE_FEATURE)" || fail "PREACTIVATE_FEATURE unsupported"
    leap_post "$LEAP_API" /v1/producer/schedule_protocol_feature_activations "{\"protocol_features_to_activate\":[\"$preact\"]}" >/dev/null \
        || fail "scheduling PREACTIVATE_FEATURE failed"
    wait_feature PREACTIVATE_FEATURE "$preact"
    leap_tapos_push "$dev_key" setcode eosio "$boot_wasm" || fail "boot setcode failed"
    leap_tapos_push "$dev_key" setabi eosio "$boot_abi" || fail "boot setabi failed"
    wtmsig="$(feature_digest WTMSIG_BLOCK_SIGNATURES)" || fail "WTMSIG_BLOCK_SIGNATURES unsupported"
    leap_tapos_push "$dev_key" raw eosio activate eosio "$wtmsig" || fail "feature activation failed"
    wait_feature WTMSIG_BLOCK_SIGNATURES "$wtmsig"
    leap_tapos_push "$dev_key" setcode eosio "$bios_wasm" || fail "bios setcode failed"
    leap_tapos_push "$dev_key" setabi eosio "$bios_abi" || fail "bios setabi failed"
    local name wif pubhex _eos
    while read -r name wif pubhex _eos; do
        leap_tapos_push "$dev_key" newaccount "$name" || fail "producer account $name failed"
    done <"$WORK_DIR/bp-keys.txt"
    local setprods_hex
    setprods_hex="$(python3 -I - "$WORK_DIR/bp-keys.txt" <<'PYEOF'
import struct, sys
rows = [l.split() for l in open(sys.argv[1]) if l.strip()]
def sym(c):
    if "a" <= c <= "z":
        return ord(c) - ord("a") + 6
    if "1" <= c <= "5":
        return ord(c) - ord("1") + 1
    return 0
def name_to_u64(s):
    v = 0
    for i in range(12):
        v = (v << 5) | sym(s[i] if i < len(s) else ".")
    return (v << 4) | (sym(s[12]) if len(s) == 13 else 0)
out = bytearray([len(rows)])
for name, _wif, pubhex, _eos in rows:
    key = bytes.fromhex(pubhex)
    assert len(key) == 33
    out += struct.pack("<Q", name_to_u64(name)) + bytes([0]) + struct.pack("<I", 1)
    out += bytes([1]) + bytes([0]) + key + struct.pack("<H", 1)
print(bytes(out).hex())
PYEOF
)" || fail "setprods encoding failed"
    leap_tapos_push "$dev_key" raw eosio setprods eosio "$setprods_hex" || fail "setprods failed"
    echo "handover: schedule proposed; waiting for the four producers to take over..."
    local active_n=0
    for _ in $(seq 1 120); do
        active_n="$(leap_post "$LEAP_API" /v1/chain/get_producer_schedule '{}' 2>/dev/null \
            | python3 -I -c 'import json,sys; a=json.load(sys.stdin)["active"]; print(len(a["producers"]) if a["version"] >= 1 else 0)' 2>/dev/null || echo 0)"
        [[ "$active_n" == "4" ]] && break
        sleep 2
    done
    [[ "$active_n" == "4" ]] || fail "the four-producer schedule never activated"
    # Every XPR node must follow the new producers: equal head and an
    # advancing LIB on the genesis relay and both validators.
    local lib1 lib2
    lib1="$(leap_head_lib "$LEAP_API" | cut -d' ' -f2)"
    for _ in $(seq 1 60); do
        sleep 2
        lib2="$(leap_head_lib "$LEAP_API" | cut -d' ' -f2)"
        [[ "${lib2:-0}" -gt "${lib1:-0}" ]] && break
    done
    [[ "${lib2:-0}" -gt "${lib1:-0}" ]] || fail "LIB stalled under the four-producer schedule"
    echo "handover: four producers active (schedule v1), LIB advancing ($lib1 -> $lib2)"
}
# Seed the fixture producers table with the four members (and no genesis
# producer row): the gate requires the declared set to equal the checkpoint's
# active producer set exactly, in both directions.
multikey_plant_producers_table() { # $1=eosio wif
    local wif="$1" name _w pubhex _eos votes_hex
    local seed_wasm="$REPO_ROOT/contracts/cutover/seed.wasm" seed_abi="$REPO_ROOT/contracts/cutover/seed.abi"
    [[ -f "$seed_wasm" && -f "$seed_abi" ]] || fail "seed contract not built (contracts/cutover)"
    votes_hex="$(python3 -c 'import struct; print(struct.pack("<d", 1.0).hex())')"
    leap_tapos_push "$wif" setcode eosio "$seed_wasm" || fail "seed setcode failed"
    leap_tapos_push "$wif" setabi eosio "$seed_abi" || fail "seed setabi failed"
    while read -r name _w pubhex _eos; do
        leap_tapos_push "$wif" cseed eosio eosio "$name" "$votes_hex" "$pubhex" 1 || fail "seed setprod $name failed"
    done <"$WORK_DIR/bp-keys.txt"
    leap_wait_effect "seeded producers rows" /v1/chain/get_table_rows \
        '{"json":true,"code":"eosio","scope":"eosio","table":"producers","limit":10}' \
        'len(json.load(sys.stdin)["rows"])' "4"
    echo "handover: fixture producers rows planted (four members, distinct keys)"
}
# Fetch one (get_block, get_block_header_state) pair for a post-H height
# ($1) from one Leap node ($2, default the producer) into the freeze work
# dir as block-post-<n>.json/.state.json. (H's own pair is staged
# separately at the freeze instant.) Writes via .tmp+mv so a
# failed fetch never leaves a half file. Returns nonzero WITHOUT failing
# when the pair is not servable yet; the caller retries. Pre-pause
# capture must use the producer (validators lag it); post-pause top-up
# must use a validator (the producer is SIGSTOPped and answers nothing).
# Either way every pair has to be captured while its block is still
# reversible; a block that goes irreversible before its pair lands
# supersedes the round.
prefetch_pair() { # $1=height [$2=api]
    local n="$1" api block_file state_file
    api="${2:-$LEAP_API}"
    block_file="$WORK_DIR/block-post-$n.json"; state_file="$WORK_DIR/block-post-$n.state.json"
    [[ -f "$block_file" && -f "$state_file" ]] && return 0
    curl --fail --silent --max-time 10 -X POST "$api/v1/chain/get_block" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' \
        -d "{\"block_num_or_id\":\"$n\"}" >"$block_file.tmp" || return 1
    leap_post "$api" /v1/chain/get_block_header_state "{\"block_num_or_id\":\"$n\"}" \
        >"$state_file.tmp" || { rm -f "$block_file.tmp" "$state_file.tmp"; return 1; }
    mv "$block_file.tmp" "$block_file"
    mv "$state_file.tmp" "$state_file"
    return 0
}
# Stage pairs for every height H..P (globals supply H via prefetch_pair),
# querying $3 (default the producer). Returns nonzero when a height never
# becomes servable: the caller must supersede the round (unpause + new
# H), never stage a gap.
top_up_pairs() { # $1=H $2=P [$3=api]
    local top_n top_try api
    api="${3:-$LEAP_API}"
    top_n="$1"
    while [[ "$top_n" -le "$2" ]]; do
        top_try=0
        while ! prefetch_pair "$top_n" "$api"; do
            top_try="$((top_try + 1))"
            [[ "$top_try" -ge 10 ]] && return 1
            sleep 0.5
        done
        top_n="$((top_n + 1))"
    done
    return 0
}
# Submit an issueTx-format body to Leap's send_transaction; prints the txid.
# Fails LOUD: curl errors used to be swallowed by --fail --silent inside a
# pipefail pipeline, so a duplicate or rejected transaction killed the run
# via a bare set -e exit with no diagnosis (stale chain data from a reused
# compose volume made every rerun hit "account already exists"). Retries
# cover transient connection stalls; a persistent rejection aborts here.
# curl runs without --fail so a 4xx/5xx keeps its JSON body (the node's
# reason for rejecting) instead of collapsing to "error: 500".
leap_send() {
    local body send_out attempt
    body="$(printf '%s' "$1" | python3 -c 'import json,sys; p=json.load(sys.stdin)["params"]; print(json.dumps({"signatures":p["signatures"],"compression":"none","packed_context_free_data":p["packed_context_free_data"],"packed_trx":p["packed_trx"]}))')" \
        || { echo "handover: leap_send: refusing to submit an unparseable issueTx body" >&2; return 1; }
    for attempt in 1 2 3; do
        # Pipe the body via stdin (@-), never argv: a setcode packed_trx
        # with inlined WASM exceeds Linux MAX_ARG_STRLEN (128 KiB per
        # string) and exec fails with "Argument list too long".
        # `if` (not `&& break`) so a handled retry does not fire the ERR trap.
        if send_out="$(printf '%s' "$body" | curl --silent --show-error --max-time 15 -X POST "$LEAP_API/v1/chain/send_transaction" \
            -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d @- 2>&1)"; then
            break
        fi
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
# Newest runner network dir wins. The dir names embed their creation time
# (network_YYYYMMDD_HHMMSS), so pick by name: directory mtimes are not
# creation times (a dir touched at shutdown or by a resumed run looks newer
# than the network that is actually live), and a stale dir made the relaunch
# look for processes that no longer existed.
newest_netdir() {
    local netdir="" cand
    for cand in "${TMPDIR:-/tmp}"/network-runner-root-data/network_* /tmp/network-runner-root-data/network_*; do
        [[ -d "$cand" ]] || continue
        # Ignore networks from before this boot began: until the runner
        # creates its dir, the "newest" one is the previous run's, and its
        # refusals would be mistaken for this boot's.
        if [[ -n "${NETDIR_FLOOR:-}" && "$(basename "$cand")" < "network_$NETDIR_FLOOR" ]]; then continue; fi
        if [[ -z "$netdir" || "$(basename "$cand")" > "$(basename "$netdir")" ]]; then netdir="$cand"; fi
    done
    printf '%s' "$netdir"
}
# True once ALL five node logs show the restore gate refusing the platform
# binding. That refusal is final for this boot (the nodes never serve an
# RPC), so the wait loop stops polling instead of burning its whole budget.
# One node's refusal is not enough: the runner restarts the nodes one by
# one to track the subnet, and a restart in flight leaves no process to
# capture for the in-place relaunch.
boot_refused_platform_binding() {
    local netdir n
    netdir="$(newest_netdir)"
    [[ -n "$netdir" ]] || return 1
    for n in 1 2 3 4 5; do
        grep -q "halt confirmation platform chain id does not match" "$netdir/node$n/logs/main.log" 2>/dev/null || return 1
    done
}
# Direct chain-RPC discovery that does not depend on the runner server:
# the runner's control API can wedge behind a pending `control start`
# (a first boot refused at the restore gate never returns, so list-rpcs
# times out on every poll), while the nodes themselves are healthy and
# serving. Probe each node's platform API for its chains and return the
# first URL answering pulsevm.getInfo with a real result. Short timeouts:
# unresponsive endpoints must not stall a poll iteration.
direct_chain_rpc_url() {
    local netdir node cfg port chains id url body
    netdir="$(newest_netdir)"
    [[ -n "$netdir" ]] || return 1
    for node in 1 2 3 4 5; do
        cfg="$netdir/node$node/configs/config.json"
        [[ -f "$cfg" ]] || continue
        port="$(jq -er '.["http-port"]' "$cfg" 2>/dev/null || true)"
        [[ -n "$port" ]] || continue
        chains="$(curl --fail --silent --max-time 3 -X POST "http://127.0.0.1:$port/ext/P" \
            -H 'Content-Type: application/json' \
            -d '{"jsonrpc":"2.0","id":1,"method":"platform.getBlockchains"}' 2>/dev/null \
            | jq -r '.result.blockchains[]?.id // empty' 2>/dev/null || true)"
        [[ -n "$chains" ]] || continue
        while IFS= read -r id; do
            [[ -n "$id" ]] || continue
            url="http://127.0.0.1:$port/ext/bc/$id/rpc"
            body="$(curl --fail --silent --max-time 3 -X POST "$url" \
                -H 'Content-Type: application/json' \
                -d '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' 2>/dev/null || true)"
            [[ -n "$body" ]] || continue
            if printf '%s' "$body" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("result") else 1)' 2>/dev/null; then
                printf '%s' "$url"
                return 0
            fi
        done <<<"$chains"
    done
    return 1
}
chain_rpc_url() {
    # Bound the call: a dead endpoint otherwise stalls each poll iteration.
    # Uses the runner's own dial/request timeouts instead of GNU `timeout`,
    # which does not exist on macOS (without this, discovery silently
    # returns empty on Mac hosts and every boot dies with "RPC never came
    # up" while the network underneath is healthy).
    # list-rpcs reports the full handler URL including the /rpc suffix: keep
    # it, since the bare /ext/bc/<id> base answers 404.
    local url
    url="$("$NETWORK_RUNNER" control list-rpcs --endpoint="$(runner_endpoint)" \
        --dial-timeout 5s --request-timeout 15s 2>/dev/null \
        | sed $'s/\033\[[0-9;]*m//g' \
        | grep -oE 'http://127\.0\.0\.1:[0-9]+/ext/bc/[A-Za-z0-9]+/rpc' | head -1 || true)"
    if [[ -n "$url" ]]; then
        printf '%s' "$url"
        return 0
    fi
    # Fallback for the wedged-API case above: the runner server can stop
    # answering while its nodes are healthy (pending start never returns),
    # so discover their chain RPCs directly instead of failing the run.
    direct_chain_rpc_url || true
}
rpc_call() {
    curl --fail --silent --max-time 15 -X POST "$1" \
        -H 'Content-Type: application/json' -d "$2"
}

# Both Leap's disk monitor and MetalGo's node health gate refuse below
# 10% free — on a nearly-full workstation a healthy rehearsal dies minutes
# in with a stall that looks like a code bug. Check the headroom first and
# fail in one second with the real cause instead.
require_disk_headroom() {
    if ! python3 -c 'import os,sys
for path in ("/System/Volumes/Data", "/tmp"):
    try: st = os.statvfs(path)
    except OSError: continue
    free = st.f_bavail * st.f_frsize / 2**30
    total = st.f_blocks * st.f_frsize / 2**30
    pct = 100.0 * st.f_bavail / st.f_blocks if st.f_blocks else 0
    print(f"handover: disk {path}: {free:.0f} GiB free of {total:.0f} GiB ({pct:.1f}%)")
    if pct < 12: sys.exit(1)
sys.exit(0)' 2>/dev/null; then
        fail "insufficient free disk: keep at least 12% free (Leap resmon and MetalGo health both refuse below 10%). Free space, then re-run"
    fi
}

cmd_start() {
    [[ ! -e "$WORK_DIR" ]] || fail "work directory exists: $WORK_DIR (run stop first)"
    mkdir -p "$WORK_DIR"
    require_disk_headroom
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
    # Multi-key mode installs the four-producer schedule first, so traffic
    # (and its dependent key rotation) runs under real multi-producer
    # production, microforks included.
    if multikey_enabled; then
        multikey_install_schedule
    fi
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
    # The rotation depends on t3 existing: wait for the account instead of
    # leaning on send retries (the first attempt used to be a rejected 500).
    for _ in $(seq 1 60); do
        leap_post "$LEAP_API" /v1/chain/get_account '{"account_name":"t3"}' >/dev/null 2>&1 && break
        sleep 1
    done
    echo "handover: traffic rotate t3: $(submit_leap updateauth "$leap_chain" "$DEV_KEY" "$leap_ref" "$leap_prefix" "$leap_exp" t3 active owner "$TRAFFIC_PUB")"
    echo "handover: waiting for the traffic accounts to exist..."
    for _ in $(seq 1 60); do
        leap_post "$LEAP_API" /v1/chain/get_account '{"account_name":"t1"}' >/dev/null 2>&1 \
        && leap_post "$LEAP_API" /v1/chain/get_account '{"account_name":"t2"}' >/dev/null 2>&1 \
        && leap_post "$LEAP_API" /v1/chain/get_account '{"account_name":"t3"}' >/dev/null 2>&1 && break
        sleep 2
    done
    # The pre-halt reference state must be irreversible state. With several
    # producers a microfork at a turn boundary can drop a transaction a node
    # already applied (the dependent t3 key rotation was observed that way),
    # so the head is not a safe thing to compare against: wait for LIB to pass
    # the head, require the rotation to be in that state (t3 active key equals
    # t1's, which was born under the traffic key), and resubmit it if it was
    # dropped.
    local rot_try cap_head cap_lib t1_key t3_key
    for rot_try in 1 2 3 4 5; do
        read -r cap_head cap_lib <<<"$(leap_head_lib "$LEAP_API")"
        for _ in $(seq 1 180); do
            read -r _h cap_lib <<<"$(leap_head_lib "$LEAP_API")"
            [[ "${cap_lib:-0}" -ge "$cap_head" ]] && break
            sleep 1
        done
        [[ "${cap_lib:-0}" -ge "$cap_head" ]] || fail "traffic never went irreversible (head $cap_head, LIB ${cap_lib:-?})"
        t1_key="$(leap_post "$LEAP_API" /v1/chain/get_account '{"account_name":"t1"}' | python3 -I -c 'import json,sys; print([p for p in json.load(sys.stdin)["permissions"] if p["perm_name"]=="active"][0]["required_auth"]["keys"][0]["key"])')" \
            || fail "could not read t1 active key"
        t3_key="$(leap_post "$LEAP_API" /v1/chain/get_account '{"account_name":"t3"}' | python3 -I -c 'import json,sys; print([p for p in json.load(sys.stdin)["permissions"] if p["perm_name"]=="active"][0]["required_auth"]["keys"][0]["key"])')" \
            || fail "could not read t3 active key"
        [[ "$t1_key" == "$t3_key" ]] && break
        echo "handover: t3 key rotation is not in irreversible state (attempt $rot_try); resubmitting..."
        leap_tapos_push "$DEV_KEY" updateauth t3 active owner "$TRAFFIC_PUB" || fail "t3 rotation resubmit failed"
    done
    [[ "$t1_key" == "$t3_key" ]] || fail "t3 key rotation never landed irreversibly"
    echo "handover: traffic is irreversible and the t3 rotation is in state (LIB $cap_lib >= head $cap_head)"
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

plant_fixture_producers_table() { # $1=eosio wif $2=roster key (EOS or PUB_K1_)
    # Deploy the seed helper onto eosio and emplace the fixture producers
    # row (owner eosio, roster schedule key, active). The row's binary
    # layout is the 8-field mainnet producer_info shape the restore gate
    # decodes; the key arrives as 33 compressed bytes (b58-decoded like
    # the contract path's roster handling).
    local wif="$1" roster_key="$2" key33 votes_hex
    local seed_wasm="$REPO_ROOT/contracts/cutover/seed.wasm"
    local seed_abi="$REPO_ROOT/contracts/cutover/seed.abi"
    [[ -f "$seed_wasm" && -f "$seed_abi" ]] || fail "seed contract not built (contracts/cutover)"
    key33="$(python3 - "$roster_key" <<'PYEOF'
import hashlib, sys
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(text):
    value = 0
    for char in text:
        value = value * 58 + B58.index(char)
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + raw
if sys.argv[1].startswith("EOS"):
    body, suffix = sys.argv[1][3:], b""
else:
    body, suffix = sys.argv[1][len("PUB_K1_"):], b"K1"
raw = b58decode(body)
assert len(raw) == 37 and raw[0] in (2, 3), "not a compressed K1 key"
assert hashlib.new("ripemd160", raw[:-4] + suffix).digest()[:4] == raw[-4:], "bad checksum"
print(raw[:33].hex())
PYEOF
)" || fail "seed roster key decode failed"
    [[ "${#key33}" == 66 ]] || fail "seed key is not 33 compressed bytes"
    votes_hex="$(python3 -c 'import struct; print(struct.pack("<d", 1.0).hex())')"
    leap_tapos_push "$wif" setcode eosio "$seed_wasm" || fail "seed setcode failed"
    echo "handover: seed helper deployed on eosio"
    leap_tapos_push "$wif" setabi eosio "$seed_abi" || fail "seed setabi failed"
    leap_tapos_push "$wif" cseed eosio eosio eosio "$votes_hex" "$key33" 1 \
        || fail "seed setprod failed"
    echo "handover: fixture producers row planted (eosio active under roster key)"
    leap_wait_effect "seeded producers row" /v1/chain/get_table_rows \
        '{"json":true,"code":"eosio","scope":"eosio","table":"producers","limit":1}' \
        'json.load(sys.stdin)["rows"][0]["owner"]' "eosio"
}

# Wait for a detached snapshot (multi-key mode) and fill SNAP_NAME/SNAP_HID.
snapshot_resolve() {
    [[ "${SNAP_PENDING:-0}" == "1" ]] || return 0
    local f="$WORK_DIR/snap-result-$H.json" out
    for _ in $(seq 1 180); do
        [[ -s "$f" ]] && break
        sleep 1
    done
    [[ -s "$f" ]] || fail "detached snapshot for H=$H never completed"
    out="$(python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r.get("error") or "", r.get("snapshot_name",""), r.get("head_block_id",""))' "$f")" \
        || fail "detached snapshot result unreadable"
    [[ "$out" != " "* ]] || true
    set -- $out
    [[ "$#" == 2 ]] || fail "detached snapshot failed: $out"
    SNAP_NAME="$1"
    SNAP_HID="$2"
    SNAP_PENDING=0
    echo "handover: snapshot $SNAP_NAME at $SNAP_HID"
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
    if multikey_enabled; then
        multikey_write_roster "$WORK_DIR/roster.json"
    else
        printf '[{"producer":"eosio","key":"%s","weight":1}]' "$roster_key" >"$WORK_DIR/roster.json"
    fi
    # The restore gate binds the roster to the on-chain producers table
    # and fails closed when it is absent (real XPR always carries it).
    # The fixture chain runs no system contract, so plant the synthetic
    # row with the seed helper before H: code eosio / scope eosio, exact
    # producer_info layout, fixture producer active under the roster key.
    # The snapshot export then carries it and the boot cross-check runs.
    if multikey_enabled; then
        multikey_plant_producers_table "$halt_key"
    else
        plant_fixture_producers_table "$halt_key" "$roster_key"
    fi
    local producer_cid
    if multikey_enabled; then
        producer_cid="$(multikey_cids)"
    else
        producer_cid="$(cd "$SCRIPT_DIR" && docker compose -f compose.yaml ps -q xpr-producer)"
    fi
    [[ -n "$producer_cid" ]] || fail "xpr-producer container not found"
    # H, DECL_DIGEST, MEMO_BLOCK, K stay global (like the legacy loop's H):
    # the shared tail below and cmd_boot read them and their files.
    local round
    round=0
    H=""
    while [[ -z "$H" ]]; do
        round="$((round + 1))"
        # Pausing four containers lands a block or two late fairly often, and each
        # miss just supersedes the round, so multi-key mode gets more rounds.
        local max_rounds="${CUTOVER_ROUNDS:-$(multikey_enabled && echo 6 || echo 3)}"
        [[ "$round" -le "$max_rounds" ]] || fail "freeze missed the declared H $max_rounds times; aborting"
        local x_chain x_head
        read -r x_chain x_head _ <<<"$(leap_chain_head "$LEAP_API")"
        # The declare->memo->scan phase takes ~10-16 blocks; the lag must
        # clear it with margin or every round overshoots before freezing.
        H="$((x_head + ${CUTOVER_LAG:-30}))"
        # Round-scoped pair files carry the height in content, not in name:
        # a superseded round must not leak its blocks into the next one.
        rm -f "$WORK_DIR/block-H.json" "$WORK_DIR/block-H.state.json" \
            "$WORK_DIR"/block-post-*.json "$WORK_DIR"/block-post-*.state.json
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
            # The freeze takes the schedule explicitly: the single fixture
            # member (eosio on the dev key) at the live active version. A
            # rotation before H fails the unanimity check below.
            local live_version roster_key_hex
            live_version="$(leap_post "$LEAP_API" /v1/chain/get_producer_schedule '{}' \
                | python3 -c 'import json,sys; print(json.load(sys.stdin)["active"]["version"])')" \
                || fail "could not read live schedule version"
            roster_key_hex="$(python3 - "$roster_key" <<'PYEOF2'
import hashlib, sys
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(text):
    value = 0
    for char in text:
        value = value * 58 + B58.index(char)
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + raw
def compressed(key):
    if key.startswith("EOS"):
        body, suffix = key[3:], b""
    else:
        body, suffix = key[len("PUB_K1_"):], b"K1"
    raw = b58decode(body)
    assert len(raw) == 37 and raw[0] in (2, 3), "not a compressed K1 key"
    assert hashlib.new("ripemd160", raw[:-4] + suffix).digest()[:4] == raw[-4:], "bad checksum"
    return raw[:33].hex()
print(compressed(sys.argv[1]))
PYEOF2
)" || fail "roster key decode failed"
            local init_hex
            init_hex="$(python3 - "$H" "$x_chain" "$live_version" "$roster_key_hex" <<'PYEOF2'
import struct, sys
def varuint(v):
    out = b""
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])
def name_to_u64(name):
    charmap = ".12345abcdefghijklmnopqrstuvwxyz"
    def sym(c):
        if "a" <= c <= "z":
            return ord(c) - ord("a") + 6
        if "1" <= c <= "5":
            return ord(c) - ord("1") + 1
        return 0
    v = 0
    for i in range(12):
        v = (v << 5) | sym(name[i] if i < len(name) else ".")
    return (v << 4) | (sym(name[12]) if len(name) == 13 else 0)
h, chain, version, key = int(sys.argv[1]), bytes.fromhex(sys.argv[2]), int(sys.argv[3]), bytes.fromhex(sys.argv[4])
out = bytearray(struct.pack("<I", h) + chain + struct.pack("<I", version))
out += varuint(1) + struct.pack("<Q", name_to_u64("eosio")) + varuint(0) + key
print(bytes(out).hex())
PYEOF2
)" || fail "contract init packing failed"
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
            local scan_to scan_log scan_votes
            scan_log="$WORK_DIR/scan-round$round.log"
            # The counted-vote wait can observe the vote in pending
            # (unconfirmed) state, freezing scan_to ahead of the vote's
            # block. Re-scan to a fresh head until the vote is actually
            # in a block instead of failing on the first empty window.
            for _scan_attempt in $(seq 1 5); do
                scan_to="$(leap_chain_head "$LEAP_API" | cut -d' ' -f2)"
                if ! "$SCANNER_BIN" --api "$LEAP_API" --contract "$CONTRACT_ACCT" --from "$x_head" --to "$scan_to" \
                    --singleton-block "$scan_to" --out "$WORK_DIR/fragment.json" \
                    --declare-out "$WORK_DIR/declaration.json" \
                    --host-header '0.0.0.0:8888' >"$scan_log" 2>&1; then
                    tail -5 "$scan_log"
                    fail "vote scan failed"
                fi
                scan_votes="$(python3 -c 'import json; print(len(json.load(open("'"$WORK_DIR/fragment.json"'"))["votes"]))' || echo -1)"
                if [[ "$scan_votes" != "0" && "$scan_votes" != "-1" ]]; then
                    break
                fi
                echo "handover: scanner saw no votes to $scan_to yet (attempt $_scan_attempt/5), re-scanning..."
                sleep 5
            done
            [[ "$scan_votes" != "0" && "$scan_votes" != "-1" ]] || fail "vote scan found no votes after 5 attempts"
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
        ceremony_key_args "$halt_key"
        decl_out="$("$CEREMONY_BIN" declare --height "$H" --source-chain "$x_chain" --roster "$WORK_DIR/roster.json" "${CEREMONY_KEY_ARGS[@]}" --out "$WORK_DIR/declaration.json")" \
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
        # migrated too, and so the inclusion proof can re-decode them. The
        # file is a chunk-ordered list (JSON objects are unordered, and the
        # chunk order is what the digest decodes from).
        python3 - "$LEAP_API" "$WORK_DIR/memo-accounts.json" $memo_names <<'PYEOF' || fail "memo account capture failed"
import json, sys, time, urllib.request
api, out, names = sys.argv[1], sys.argv[2], sys.argv[3:]
accts = []
for name in names:
    for _ in range(30):
        try:
            req = urllib.request.Request(api + "/v1/chain/get_account",
                                         data=json.dumps({"account_name": name}).encode(),
                                         headers={"Content-Type": "application/json",
                                                  "Host": "0.0.0.0:8888"})
            with urllib.request.urlopen(req, timeout=15) as r:
                accts.append({"name": name, "account": json.load(r)})
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
        #
        # The same instant also captures H's (block, header-state) pair:
        # header state is only served while a block is still reversible, so
        # fetching here, in the same poll iteration that first sees head==H,
        # is the only reliable capture. The state is bound to the snapshotted
        # head id below; a foreign state fails there, not at the gate.
        echo "handover: round $round snapshotting the running producer at H=$H..."
        local snap_info snap_code
        snap_code=0
        rm -f "$WORK_DIR/snap-result-$H.json"
        snap_info="$(HANDOVER_ASYNC_SNAPSHOT="$(multikey_enabled && echo 1 || echo 0)" python3 - "$LEAP_API" "$H" "$WORK_DIR" <<'PYEOF'

import json, os, sys, time, urllib.request
api, H, workdir = sys.argv[1], int(sys.argv[2]), sys.argv[3]
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
try:
    block = post("/v1/chain/get_block", {"block_num_or_id": H})
    state = post("/v1/chain/get_block_header_state", {"block_num_or_id": H})
except Exception as e:
    print(f"H={H} pair capture failed: {e}", file=sys.stderr)
    sys.exit(2)
with open(f"{workdir}/block-H.json", "w") as f:
    json.dump(block, f)
with open(f"{workdir}/block-H.state.json", "w") as f:
    json.dump(state, f)
# Header state is only served while a block is still reversible, and H is
# the head in this exact poll iteration — the only moment its state is
# guaranteed servable. (No export nodeos can serve it later: a node
# hydrated from the H snapshot takes H as its irreversible base, and
# Leap serves header state for reversible blocks only. So the authoritative
# schedule the proof authenticates against is captured here, from this
# synced node, bound below to the snapshotted H id — never from a live
# get_producer_schedule query, whose pending schedule may already have
# moved on, and never from the producers table.)
if state.get("id") != block.get("id"):
    print(f"header state is not for H={H}: {state.get('id')} != {block.get('id')}", file=sys.stderr)
    sys.exit(2)
if os.environ.get("HANDOVER_ASYNC_SNAPSHOT") == "1":
    # With several producers create_snapshot takes tens of blocks to return,
    # and the agreed stop sits at most a few blocks past H. Fire it in a
    # detached child and keep capturing post-H pairs; the caller resolves
    # the result file before it is needed. The file is per-H so a child from
    # a superseded round can never answer a later one.
    if os.fork() == 0:
        os.setsid()
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(devnull, fd)
        result = {}
        try:
            result = post("/v1/producer/create_snapshot", {})
        except Exception as e:
            result = {"error": str(e)}
        tmp = f"{workdir}/snap-result-{H}.json.tmp"
        with open(tmp, "w") as f:
            json.dump(result, f)
        os.rename(tmp, f"{workdir}/snap-result-{H}.json")
        os._exit(0)
    print(f"ASYNC {block['id']}")
    sys.exit(0)
snap = post("/v1/producer/create_snapshot", {})
n, hid = snap.get("snapshot_name", ""), snap.get("head_block_id", "")
if not n or not hid:
    print(f"snapshot failed at H={H}: {snap}", file=sys.stderr)
    sys.exit(1)
if hid != block.get("id"):
    print(f"snapshot slipped past H={H}: {hid} != {block.get('id')}", file=sys.stderr)
    sys.exit(2)
if state.get("id") != hid:
    print(f"header state is not for H={H}: {state.get('id')} != {hid}", file=sys.stderr)
    sys.exit(2)
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
        # ASYNC: the snapshot is still being written by a detached child;
        # snapshot_resolve fills SNAP_NAME/SNAP_HID after the freeze.
        SNAP_PENDING=0
        if [[ "$SNAP_NAME" == "ASYNC" ]]; then
            SNAP_PENDING=1
            SNAP_NAME="pending"
        fi
        [[ -n "$SNAP_NAME" && -n "$SNAP_HID" ]] || fail "producer snapshot returned no name/id"
        echo "handover: snapshot $SNAP_NAME at $SNAP_HID"
        # Agreed stop: P is fixed up front (H + STOP_LAG), never observed.
        # Every producer stops at the same agreed P — the fleet pact and
        # the voter enforce it — and the 15-of-21 confirmation quorum over
        # H_ID stands in for Leap finality. So there is NO LIB wait: on a
        # large committee LIB(H) arrives hundreds of blocks after the
        # agreed stop, and waiting for it deadlocks the halt while the
        # chain builds an unproven tail past the proof window.
        #
        # The loop below streams post-H pairs while the producer still
        # builds: header state is served while a block is reversible, so
        # every H+1..P tip is fetched the moment it appears. The pause then
        # lands exactly on P, and only tip blocks produced during pause
        # latency can still be missing (topped up afterwards — the fresh tip
        # is always reversible because LIB trails production).
        # A Leap snapshot of H only finalizes once H is irreversible, so the
        # agreed stop must sit past the finality lag: P - H >= 2 x (head -
        # LIB) + 12, the same rule the voter's preflight enforces. A single
        # producer has a lag of ~1 and keeps the historical 5; several
        # producers derive it from the live gap. CUTOVER_STOP_LAG overrides.
        local fin_head fin_lib fin_lag fin_need
        read -r fin_head fin_lib <<<"$(leap_head_lib "$LEAP_API")"
        fin_lag="$((${fin_head:-0} - ${fin_lib:-0}))"
        fin_need="$((2 * fin_lag + 12))"
        if [[ "$fin_lag" -le 3 ]]; then fin_need=5; fi
        CUTOVER_STOP_LAG="${CUTOVER_STOP_LAG:-$fin_need}"
        if [[ "$CUTOVER_STOP_LAG" -lt "$fin_need" ]]; then
            fail "CUTOVER_STOP_LAG=$CUTOVER_STOP_LAG is inside the finality lag (head-LIB $fin_lag, need >= $fin_need): the H snapshot would never finalize"
        fi
        P_AGREED=$((H + CUTOVER_STOP_LAG))
        echo "handover: finality lag $fin_lag; agreed stop P=$P_AGREED (H+$CUTOVER_STOP_LAG)"
        # How many blocks before P to start freezing (learned from misses;
        # see the freeze step). The capture loop must stop at the same point,
        # or the freeze only starts after head has already reached P and the
        # lead changes nothing. Pairs for the last few blocks are fetched
        # from a validator after the pause (top_up_pairs), as they always
        # were for blocks produced during the pause latency.
        PAUSE_LEAD="${PAUSE_LEAD:-${CUTOVER_PAUSE_LEAD:-0}}"
        echo "handover: round $round capturing post-H pairs until the agreed stop P=$P_AGREED (pause lead $PAUSE_LEAD)..."
        local attempt next_fetch
        next_fetch=$((H + 1))
        for attempt in $(seq 1 900); do
            local prod_head
            prod_head="$(leap_head_lib "$LEAP_API" 2>/dev/null | cut -d' ' -f1 || true)"
            if [[ -n "$prod_head" ]]; then
                local n
                n="$next_fetch"
                while [[ "$n" -le "$prod_head" && "$n" -le "$P_AGREED" ]]; do
                    prefetch_pair "$n" && next_fetch="$((n + 1))"
                    n="$((n + 1))"
                done
                if [[ "$prod_head" -ge "$((P_AGREED - PAUSE_LEAD))" ]]; then
                    break
                fi
            fi
            [[ "$attempt" == 900 ]] && fail "producer head never reached the agreed stop P=$P_AGREED"
            sleep 0.2
        done
        # Freeze: SIGSTOP-via-pause is instant. Poll for the agreed P and
        # pause the moment it is observed; the exact-P check below rejects
        # any overshoot past P (an extra block would be an unstaged tail),
        # superseding the round like any other miss.
        echo "handover: round $round freezing the producer at the agreed stop P=$P_AGREED (snapshot holds H=$H)..."
        local freeze_code
        freeze_code=0
        # Pausing the containers takes a block or so to land, and with four
        # producers that latency is steady, so a pause triggered at P always
        # lands past it. The lead is how many blocks early to trigger; it
        # starts at CUTOVER_PAUSE_LEAD (default 0) and is learned from each
        # missed round (see below), since the right value depends on the host.
        PAUSE_LEAD="${PAUSE_LEAD:-${CUTOVER_PAUSE_LEAD:-0}}"
        python3 - "$producer_cid" "$P_AGREED" "$LEAP_API" "$PAUSE_LEAD" <<'PYEOF' || freeze_code=$?
import json, subprocess, sys, time, urllib.request
cids, target, api = sys.argv[1].split(","), int(sys.argv[2]), sys.argv[3]
lead = int(sys.argv[4])
def head():
    req = urllib.request.Request(api + "/v1/chain/get_info", data=b"{}",
                                 headers={"Content-Type": "application/json",
                                          "Host": "0.0.0.0:8888"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)["head_block_num"]
deadline = time.time() + 120
h = head()
while h < target - lead:
    if time.time() > deadline:
        print(f"head never reached H={target}", file=sys.stderr)
        sys.exit(1)
    time.sleep(0.01)
    h = head()
# Every producer pauses at once: in multi-key mode the schedule has four
# members and any one left running keeps building past P.
procs = [subprocess.Popen(["docker", "pause", c], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for c in cids]
for proc in procs:
    _out, err = proc.communicate()
    if proc.returncode != 0:
        print(f"docker pause failed: {err}", file=sys.stderr)
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
        # The pause head must sit exactly on the agreed stop: any block past
        # P would be an unstaged tail outside the H+1..P proof window, so an
        # overshoot supersedes the round like any other miss.
        if [[ -z "$P" || "$P" != "$P_AGREED" ]]; then
            echo "handover: round $round validators converged to [$v1] [$v2], not exactly P=$P_AGREED for H=$H; unpausing, retrying..."
            # Learn the pause latency: trigger earlier by however many
            # blocks the freeze overshot (or later by the undershoot).
            if [[ "$P" =~ ^[0-9]+$ ]]; then
                PAUSE_LEAD=$((PAUSE_LEAD + P - P_AGREED))
                [[ "$PAUSE_LEAD" -ge 0 ]] || PAUSE_LEAD=0
                [[ "$PAUSE_LEAD" -le 10 ]] || PAUSE_LEAD=10
                echo "handover: pause lead is now $PAUSE_LEAD block(s)"
            fi
            docker unpause ${producer_cid//,/ } >/dev/null 2>&1 || true
            H=""
            continue
        fi
        # Schedule cross-check: the producer capture of H's header state is
        # authoritative only if independent synced nodes agree on the frozen
        # committee. The chain is frozen at P, so both validators report the
        # same active set H ran under (keys are bound separately by
        # checkpoint state and the H signature; this checks membership and
        # version). Validators cannot re-serve H's header state itself here
        # — it went irreversible as they converged — so the active-set
        # equality is the strongest cross-node agreement available. A missing
        # or divergent report supersedes the round like any other miss.
        xcheck_ok=1
        for v_api in "$LEAP_V1_API" "$LEAP_V2_API"; do
            if ! leap_post "$v_api" /v1/chain/get_producer_schedule '{}' > "$WORK_DIR/schedule-xcheck.tmp" 2>/dev/null; then
                xcheck_ok=""
                break
            fi
            python3 -c '
import json, sys
state = json.load(open(sys.argv[1]))
live = json.load(open(sys.argv[2]))
a = state.get("active_schedule") or {}
b = live.get("active") or {}
names = lambda sch: sorted(p.get("producer_name", "") for p in sch.get("producers") or [])
sys.exit(0 if (a.get("version") == b.get("version") and names(a) == names(b)) else 1)
' "$WORK_DIR/block-H.state.json" "$WORK_DIR/schedule-xcheck.tmp" || { xcheck_ok=""; break; }
        done
        rm -f "$WORK_DIR/schedule-xcheck.tmp"
        if [[ -z "$xcheck_ok" ]]; then
            echo "handover: round $round validator active schedule disagrees with the frozen H state; unpausing, retrying..."
            docker unpause ${producer_cid//,/ } >/dev/null 2>&1 || true
            H=""
            continue
        fi
        echo "handover: frozen schedule cross-checked: both validators agree with the H state"
        echo "handover: producer paused; network frozen at P=$P (snapshot holds exact H=$H)"
        echo "$P" >"$WORK_DIR/P"
        # Converged frozen heads, kept for the audit trail: both validators
        # agreed on P, and the confirmation attests this single agreed head
        # as the quorum's pause observation (every signer confirms the same
        # P, never its own tip).
        echo "$v1_head" >"$WORK_DIR/P_V1"
        echo "$v2_head" >"$WORK_DIR/P_V2"
        # Top-up: blocks produced between the last capture poll and the
        # pause (at most the fresh tip) still lack pairs. The producer is
        # paused, so query a validator: the tip is seconds old. Anything
        # still missing means finality outran capture: supersede the round
        # like an overshoot. (H's own pair is already staged from the freeze
        # capture above, not here.)
        if ! top_up_pairs "$((H + 1))" "$P" "$LEAP_V1_API"; then
            echo "handover: round $round pair capture lost to finality for H=$H..P=$P; unpausing, retrying..."
            docker unpause ${producer_cid//,/ } >/dev/null 2>&1 || true
            H=""
            continue
        fi
        break
    done
    echo "$H" >"$WORK_DIR/H"
    echo "$MEMO_BLOCK" >"$WORK_DIR/memo-block"
    echo "$K" >"$WORK_DIR/cutover-K"
    echo "$DECL_DIGEST" >"$WORK_DIR/decl-digest"
    echo "$P_AGREED" >"$WORK_DIR/P-agreed"
    [[ -f "$WORK_DIR/block-H.json" ]] || curl --fail --silent --max-time 15 -X POST "$LEAP_V1_API/v1/chain/get_block" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' \
        -d "{\"block_num_or_id\":\"$H\"}" >"$WORK_DIR/block-H.json" || fail "get_block H=$H failed"
    H_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$WORK_DIR/block-H.json")"
    echo "$H_ID" >"$WORK_DIR/H_ID"
    echo "handover: network frozen at P=$(cat "$WORK_DIR/P"), cutover H=$H id=$H_ID; memo block $MEMO_BLOCK (K=$K)"
    # H's own header state was captured at the freeze above (block-H.state.json):
    # the attach tool records H as a gate entry from H's block plus this
    # state, so the window opens on a signature-checked H rather than a bare
    # anchor. No fetch here: header state is only served while reversible,
    # and H went irreversible as the chain built to P.
    post_n=$((H + 1))
    while [[ "$post_n" -le "$P" ]]; do
        # Pairs arrive pre-captured from the running producer; the fetches
        # below only fill gaps the top-up already closed (get_block stays
        # servable post-pause, header state does not).
        [[ -f "$WORK_DIR/block-post-$post_n.json" ]] || curl --fail --silent --max-time 15 -X POST "$LEAP_V1_API/v1/chain/get_block" \
            -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' \
            -d "{\"block_num_or_id\":\"$post_n\"}" >"$WORK_DIR/block-post-$post_n.json" \
            || fail "get_block post-H $post_n failed"
        # The header state carries the blockroot and pending-schedule hash
        # the producer signature covers: the attach tool needs it to
        # recompute Leap's signature digest for each staged header.
        [[ -f "$WORK_DIR/block-post-$post_n.state.json" ]] || leap_post "$LEAP_V1_API" /v1/chain/get_block_header_state "{\"block_num_or_id\":\"$post_n\"}" \
            >"$WORK_DIR/block-post-$post_n.state.json" \
            || fail "get_block_header_state post-H $post_n failed"
        post_n=$((post_n + 1))
    done
    echo "handover: post-H headers staged: H+1..P ($((P - H)) blocks)"
    # The snapshot was taken pre-pause on the running producer: bind it to
    # the cutover H (same id ⇒ same deterministic state) and stage it from
    # the root-owned producer volume, the legacy pattern. Blocks H+1..P are
    # the agreed proof window up to the exact stop P, staged above.
    snapshot_resolve
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
    if multikey_enabled; then
        # shellcheck disable=SC2046
        docker unpause $(multikey_cids | tr ',' ' ') >/dev/null 2>&1 || true
        (cd "$SCRIPT_DIR" && docker compose -f compose.yaml stop xpr-bp-a xpr-bp-b xpr-bp-c xpr-bp-d xpr-producer xpr-validator-1 xpr-validator-2)
    else
        docker unpause "$(cd "$SCRIPT_DIR" && docker compose -f compose.yaml ps -q xpr-producer)" >/dev/null 2>&1 || true
        (cd "$SCRIPT_DIR" && docker compose -f compose.yaml stop xpr-producer xpr-validator-1 xpr-validator-2)
    fi
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
    # P is the ceremony's agreed stop (fixed H+k before the freeze, saved
    # at freeze time; the validators' converged heads in P_V1/P_V2 are the
    # audit trail that the network actually stopped there). The gate
    # requires the post-H proof to cover exactly it. The ceremony tool
    # refuses unless every signer confirms the same agreed head, so a
    # divergent freeze fails here, not at boot.
    P="$(cat "$WORK_DIR/P")" || fail "could not read frozen head P"
    # The confirmation commits to the id of block P itself (not just its
    # height), read from the staged P header: the quorum attests this branch.
    P_ID="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$WORK_DIR/block-post-$P.json")" \
        || fail "could not read the id of block P from block-post-$P.json"
    [[ "${#P_ID}" == 64 ]] || fail "block P id is malformed: $P_ID"
    ceremony_key_args "$halt_key"
    confirm_out="$("$CEREMONY_BIN" confirm --declaration "$WORK_DIR/declaration.json" --height "$H" --pause-height "$P" --pause-block-id "$P_ID" --block-id "$H_ID" --checkpoint "$CHECKPOINT_SHA256" --genesis "$WORK_DIR/migration.genesis.json" --platform-chain-id "$platform_chain" "${CEREMONY_KEY_ARGS[@]}" --out "$WORK_DIR/confirmation.json")" \
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
        --max-confirmation-lag "${CONFIRM_LAG:-$((120 + ${CUTOVER_STOP_LAG:-5}))}"
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
    # The frozen schedule is read from H's header state, captured from the
    # coordinator's own synced node in the same poll iteration that first
    # observed head==H (header state is only served while reversible, and no
    # export nodeos can serve H later: a node hydrated from the H snapshot
    # takes H as its irreversible base). It is bound here to the
    # snapshotted H id — id prefix bytes carry the block number — so a
    # foreign state fails here with the heights attached. Never from a live
    # get_producer_schedule query, whose pending schedule may already have
    # moved on, and never from the producers table (which lists every
    # active row, not the schedule).
    # The attach tool derives both the roster's active schedule and the
    # pending/proposed absence from this same file (never hand-typed).
    # The frozen schedule pins the roster the H and post-H signatures (and
    # the declaration quorum) resolve against.
    H_STATE="$WORK_DIR/block-H.state.json"
    [[ -f "$H_STATE" ]] \
        || fail "H header state not captured at the freeze"
    h_state_num="$(python3 -c 'import json,struct,sys; print(struct.unpack(">I", bytes.fromhex(json.load(open(sys.argv[1]))["id"])[:4])[0])' "$H_STATE")" \
        || fail "could not read H header state block number"
    h_state_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$H_STATE")" \
        || fail "could not read H header state block id"
    [[ "$h_state_num" == "$H" && "$h_state_id" == "$H_ID" ]] \
        || fail "H header state is block $h_state_num $h_state_id, not H=$H $H_ID"
    echo "handover: frozen schedule bound to H=$H $H_ID"
    # A checkpoint taken mid-rotation would boot the new chain with a pending
    # proposal the ceremony never froze. Read the pending producers out of
    # H's header state and fail closed here, not at boot.
    staged_pending="$(python3 -c 'import json,sys; s = json.load(open(sys.argv[1])); print(len(((s.get("pending_schedule") or {}).get("schedule") or {}).get("producers") or []))' "$H_STATE")" \
        || fail "could not read staged pending schedule at H"
    [[ "$staged_pending" == "0" ]] \
        || fail "schedule change staged at H ($staged_pending pending producers): freeze the ceremony after it activates"
    echo "handover: no proposed schedule at H"
    attach_args+=(--halt-state "$H_STATE")
    if [[ "${CUTOVER_VEHICLE:-memo}" == "memo" ]]; then
        # The declaration-inclusion proof: the memo accounts captured at
        # declaration time (chunk-ordered list) are recorded so the gate
        # proves each name re-decodes to the declaration digest and existed
        # before H. The contract vehicle has no memo accounts.
        [[ -f "$WORK_DIR/memo-accounts.json" ]] || fail "memo accounts not captured at declaration"
        attach_args+=(--memo-accounts "$WORK_DIR/memo-accounts.json")
    fi
    post_n=$((H + 1))
    while [[ "$post_n" -le "$P" ]]; do
        [[ -f "$WORK_DIR/block-post-$post_n.json" ]] || fail "post-H header $post_n not staged"
        [[ -f "$WORK_DIR/block-post-$post_n.state.json" ]] || fail "post-H header state $post_n not staged"
        attach_args+=(--post-block "$WORK_DIR/block-post-$post_n.json" --post-state "$WORK_DIR/block-post-$post_n.state.json")
        post_n=$((post_n + 1))
    done
    # Deferred-transaction inventory: no migrated deferred may be due
    # between H and P (it would set a post-H transaction_mroot and fail
    # the boot closed at the emptiness gate). The rehearsal fixture chain
    # carries no deferred activity, so the check runs only when the export
    # staged a sidecar — mainnet exports always do.
    verify_sidecar_args=()
    if [[ -f "$export_dir/deferred-transactions.json" ]]; then
        attach_args+=(--deferred-sidecar "$export_dir/deferred-transactions.json")
        verify_sidecar_args+=(--deferred-sidecar "$export_dir/deferred-transactions.json")
    else
        echo "handover: no deferred sidecar staged; skipping the pause-window inventory check"
    fi
    "$ATTACH_BIN" \
        "$manifest" "$WORK_DIR/block-H.json" "$manifest.attached" \
        "${attach_args[@]}" \
        || fail "source block attach failed (H carries the cutoff state; only H+1..P must be empty)"
    mv "$manifest.attached" "$manifest"
    # Empty-array expansion under `set -u` aborts pre-4.4 bash (macOS):
    # branch on length instead of expanding a possibly-empty array.
    if [[ "${#verify_sidecar_args[@]}" == 0 ]]; then
        "$VERIFY_BIN" "$manifest" "$export_dir/migration.snapshot" --genesis "$WORK_DIR/migration.genesis.json" --platform-chain-id "$platform_chain" \
            || fail "offline pair verification failed"
    else
        "$VERIFY_BIN" "$manifest" "$export_dir/migration.snapshot" --genesis "$WORK_DIR/migration.genesis.json" --platform-chain-id "$platform_chain" \
            "${verify_sidecar_args[@]}" \
            || fail "offline pair verification failed"
    fi
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
    netdir="$(newest_netdir)"
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
        for _ in $(seq 1 24); do
            cmdline="$(ps -eo pid,args | grep "[m]etalgo.*$NETBASE/node$n/configs" | head -1 | sed -E 's/^ *[0-9]+ //' || true)"
            [[ -n "$cmdline" ]] && break
            sleep 5
        done
        if [[ -z "$cmdline" ]]; then
            echo "handover: metalgo processes seen at capture time (looking for $NETBASE/node$n):" >&2
            ps -eo pid,etime,args | grep "[m]etalgo" | cut -c1-240 >&2 || true
            fail "learn-then-bind: node$n process not found after retries"
        fi
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
    require_disk_headroom
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
        "$export_dir/migration.snapshot" \
        --leap-snapshot "$(cat "$WORK_DIR/snapshot")") || fail "checkpoint import failed"
    # Determinism on a REAL export: every BP converts its own export and the
    # fleet has to land on one checkpoint hash. Convert the same export a
    # second time in a separate process with a different working directory,
    # timezone, locale and thread count, and require byte-identical output.
    # (The in-repo unit test converts one hand-built entry twice in a single
    # process; this is the real-data, cross-process proof.)
    det_dir="$export_dir/determinism"
    mkdir -p "$det_dir/cwd"
    (cd "$det_dir/cwd" && \
        TZ=Pacific/Auckland LC_ALL=C RAYON_NUM_THREADS=1 \
        "$REPO_ROOT/target/debug/examples/xpr_import_check" \
        "$export_dir/state-history/chain_state_history.log" \
        "$det_dir/arena" \
        "$det_dir/migration.snapshot" \
        --leap-snapshot "$(cat "$WORK_DIR/snapshot")" >"$det_dir/convert.log" 2>&1) \
        || fail "second conversion failed (see $det_dir/convert.log)"
    first_sum="$(shasum -a 256 "$export_dir/migration.snapshot" | cut -d' ' -f1)"
    second_sum="$(shasum -a 256 "$det_dir/migration.snapshot" | cut -d' ' -f1)"
    [[ "$first_sum" == "$second_sum" ]] \
        || fail "conversion is not deterministic: $first_sum vs $second_sum"
    echo "handover: determinism: two independent conversions of the real export are byte-identical ($first_sum)"
    # The booting nodes take their own derived hash from the SECOND,
    # independent conversion (the node refuses a checkpoint whose hash this
    # operator did not derive), never from the delivered manifest.
    printf '%s\n' "$second_sum" >"$WORK_DIR/local-checkpoint.sha256"
    rm -rf "$det_dir"
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
        # The freeze plants the fixture producers row (seed helper on
        # eosio) before H on every vehicle, so the export carries it and
        # the light-client set-equality check runs and must pass — a
        # checkpoint without the table fails closed at the boot gate.
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
    # Runner dirs are named network_YYYYMMDD_HHMMSS in local time; record the
    # boot start so newest_netdir only ever sees this boot's network.
    NETDIR_FLOOR="$(date +%Y%m%d_%H%M%S)"
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
    # network must adopt the fixture identities. The default key is the
    # well-known fixture dev key: DISPOSABLE REHEARSAL ONLY, never mainnet.
    # Anything beyond a disposable local rehearsal must set
    # PULSEVM_PRODUCER_KEY explicitly (and should not use this harness).
    if [[ -z "${PULSEVM_PRODUCER_KEY:-}" ]]; then
        echo "handover: WARNING: using the fixture dev producer key (disposable rehearsal only); set PULSEVM_PRODUCER_KEY to use another"
    fi
    export PULSEVM_SYSTEM_ACCOUNT="eosio"
    export PULSEVM_PRODUCER_NAME="eosio"
    export PULSEVM_PRODUCER_KEY="${PULSEVM_PRODUCER_KEY:-5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3}"
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
    PULSEVM_LOCAL_CHECKPOINT_SHA256="$(tr -d '[:space:]' <"$WORK_DIR/local-checkpoint.sha256")" \
        || fail "no locally derived checkpoint hash recorded"
    export PULSEVM_LOCAL_CHECKPOINT_SHA256
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
    # waits. Background the loop directly (never `( ... & )`): a job
    # backgrounded inside parens belongs to the subshell, so the parent's
    # $! stays unset and `set -u` aborts the main shell with a bare
    # "unbound variable" and no FATAL line. Direct `&` sets $! reliably.
    # The loop also exits when the main shell goes away, so a dead run
    # cannot keep ticking heartbeats into the log and look alive.
    while true; do sleep 60; echo "handover: heartbeat $(date +%H:%M:%S) (cmd_boot rpc wait)"; kill -0 $PPID 2>/dev/null || exit 0; done &
    HEARTBEAT_PID=$!
    rpc_url=""
    for _wait_iter in $(seq 1 60); do
        boot_refused_platform_binding && break
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
    kill "${HEARTBEAT_PID:-}" 2>/dev/null || true
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
    memo_data = json.load(open(memo_path))
    # Chunk-ordered list of name/account pairs (the inclusion proof needs
    # the order; JSON objects would lose it).
    old.update({e["name"]: e["account"] for e in memo_data})
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
    old_chain="$(shadow_head >/dev/null 2>&1 || true; curl --fail --silent --max-time 10 -X POST "$SHADOW_RPC/" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["chain_id"])' 2>/dev/null || echo stopped)"
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
