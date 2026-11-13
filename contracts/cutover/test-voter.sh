#!/usr/bin/env bash
# Live test for the cutover auto-voter on a throwaway single-node Leap chain:
# deploys the ceremony contract, freezes a one-member schedule, then proves
# the voter (1) refuses a foreign freeze in dry-run without signing anything,
# (2) prints the exact signing digest for an external agent, (3) signs and
# submits a real vote unattended, (4) delivers the confirmation binding the
# configured platform id to a coordinator that serves live chain data --
# while refusing a coordinator that lies about the terminal block id and one
# that serves a different platform id.
set -u
cd "$(dirname "$0")/../.."
REPO_ROOT="$PWD"
SCRIPT_DIR="$REPO_ROOT/contracts/cutover"
IMG="${XPR_NODEOS_IMAGE:-pulsevm-xpr-handover:local}"
# The official Leap image uses ENTRYPOINT ["nodeos"]; the local handover image
# wraps nodeos in /entrypoint.sh and expects it as the command. Pass the
# `nodeos` word only when the image does not already run it.
if [[ "$(docker image inspect --format '{{index .Config.Entrypoint 0}}' "$IMG" 2>/dev/null)" == "nodeos" ]]; then
    NODEOS_CMD=""
else
    NODEOS_CMD="nodeos"
fi
PLATFORM="${XPR_PLATFORM:-linux/arm64}"
PORT="${VOTER_TEST_PORT:-18994}"
NODE="cutover-voter-test-node"
API="http://127.0.0.1:${PORT}"
WORK="$(mktemp -d /tmp/cutover-voter-test.XXXXXX)"
VOTER_BIN="$REPO_ROOT/target/debug/examples/xpr_cutover_voter"
PROBE_BIN="$REPO_ROOT/target/debug/examples/make_probe_tx"

fail() { echo "cutover-voter-test: FAIL: $*" >&2; exit 1; }
pass() { echo "cutover-voter-test: ok: $*"; }
cleanup() {
    docker rm -f "$NODE" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "cutover-voter-test: building tools..."
(cd "$REPO_ROOT" && cargo build --locked -p pulsevm_core --example xpr_cutover_voter --example make_probe_tx --example xpr_halt_ceremony) \
    || fail "tool build failed"
[[ -x "$VOTER_BIN" ]] || fail "voter binary missing"
[[ -x "$PROBE_BIN" ]] || fail "probe binary missing"
[[ -x "$REPO_ROOT/target/debug/examples/xpr_halt_ceremony" ]] || fail "ceremony tool binary missing"

DEV_WIF="$(grep -o 'KEY:[A-Za-z0-9]*' "$REPO_ROOT/tools/xpr-chainbase-export/localnet/producer-config.ini" | head -1 | cut -d: -f2)"
[[ -n "$DEV_WIF" ]] || fail "fixture dev key not found"

echo "cutover-voter-test: starting throwaway Leap node..."
docker rm -f "$NODE" >/dev/null 2>&1 || true
docker run --detach --platform "$PLATFORM" --name "$NODE" \
    -v "$REPO_ROOT/tools/xpr-chainbase-export/localnet/genesis.json:/config-env/genesis.json:ro" \
    -v "$REPO_ROOT/tools/xpr-chainbase-export/localnet/producer-config.ini:/config/config.ini:ro" \
    -p "127.0.0.1:${PORT}:8888" \
    "$IMG" \
    $NODEOS_CMD --data-dir=/data --config-dir=/config --genesis-json=/config-env/genesis.json ${NODEOS_EXTRA_ARGS:-} \
    >/dev/null || fail "node start failed"
for _ in $(seq 1 90); do
    HEAD_NOW="$(curl --fail --silent --max-time 5 -X POST "$API/v1/chain/get_info" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d '{}' 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])' 2>/dev/null || true)"
    if [[ -n "${HEAD_NOW:-}" && "$HEAD_NOW" -ge 10 ]]; then
        break
    fi
    sleep 1
done
[[ -n "${HEAD_NOW:-}" && "$HEAD_NOW" -ge 10 ]] || fail "node never reached head 10"

rpc() {
    local out code
    out="$(curl --silent --show-error --max-time 20 -X POST "$API$1" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d "$2" -w '\nHTTP_CODE:%{http_code}\n' 2>&1)"
    code="$(printf '%s' "$out" | grep -o 'HTTP_CODE:[0-9]*' | cut -d: -f2)"
    [[ "$code" == "200" || "$code" == "201" || "$code" == "202" ]] \
        && { printf '%s' "$out" | sed '/^HTTP_CODE:/d'; return 0; }
    echo "cutover-voter-test: rpc $1 failed (HTTP $code)" >&2
    return 1
}
tapos() {
    rpc /v1/chain/get_info '{}' | python3 -c \
        'import json,sys; i=json.load(sys.stdin); print(i["head_block_num"], i["chain_id"])'
}
ref_prefix() {
    rpc /v1/chain/get_block "{\"block_num_or_id\":$1}" | python3 -c \
        'import json,sys; b=json.load(sys.stdin); print(b["block_num"] & 0xffff, b["ref_block_prefix"])'
}
table_rows() {
    rpc /v1/chain/get_table_rows \
        "{\"code\":\"$1\",\"scope\":\"$2\",\"table\":\"$3\",\"limit\":100,\"json\":true}" \
        | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["rows"]))'
}
push_issue() {
    local body send_out http_code txid
    body="$(printf '%s' "$1" | python3 -c 'import json,sys; p=json.load(sys.stdin)["params"]; print(json.dumps({"signatures":p["signatures"],"compression":"none","packed_context_free_data":p["packed_context_free_data"],"packed_trx":p["packed_trx"]}))')" \
        || fail "unparseable issueTx body"
    send_out="$(printf '%s' "$body" | curl --silent --show-error --max-time 20 \
        -X POST "$API/v1/chain/send_transaction" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d @- -w '\nHTTP_CODE:%{http_code}\n' 2>&1)"
    http_code="$(printf '%s' "$send_out" | grep -o 'HTTP_CODE:[0-9]*' | cut -d: -f2)"
    [[ "$http_code" == "200" || "$http_code" == "201" || "$http_code" == "202" ]] \
        || fail "send_transaction rejected (HTTP $http_code): $(printf '%s' "$send_out" | head -c 400)"
    txid="$(printf '%s' "$send_out" | sed '/^HTTP_CODE:/d' | python3 -c 'import json,sys; print(json.load(sys.stdin)["transaction_id"])')" \
        || fail "no txid in response"
    printf '%s\n' "$txid"
}
mk_tx() {
    local mode="$1" chain="$2" wif="$3"
    shift 3
    local head ref_num ref_prefix exp
    head="$(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])')"
    read -r ref_num ref_prefix <<<"$(ref_prefix "$head")"
    exp=$(( $(date +%s) + 1800 ))
    "$PROBE_BIN" "$mode" "$chain" "$wif" "$ref_num" "$ref_prefix" "$exp" "$@"
}
mk_push() { push_issue "$(mk_tx "$@")"; }

read -r HEAD_NUM CHAIN_ID <<<"$(tapos)"
echo "cutover-voter-test: chain $CHAIN_ID at head $HEAD_NUM"

echo "cutover-voter-test: deploying the ceremony contract..."
# NOTE: the canonical key display form comes from the frozen on-chain row
# (see roster.json below), never hand-built.
mk_push newaccount "$CHAIN_ID" "$DEV_WIF" cutover >/dev/null
mk_push setcode "$CHAIN_ID" "$DEV_WIF" cutover "$SCRIPT_DIR/cutover.wasm" >/dev/null
mk_push setabi "$CHAIN_ID" "$DEV_WIF" cutover "$SCRIPT_DIR/cutover.abi" >/dev/null
# The freeze must name the live active schedule or the voter's
# freeze-vs-schedule check refuses: the fixture chain produces as "eosio"
# under the dev key, so the one-member schedule is exactly that.
PUB33="$("$PROBE_BIN" pubkey "$DEV_WIF")"
pass "contract deployed"

# The freeze takes the schedule explicitly: one member here, so the first
# vote finalizes. No producers table is read by the contract.
SCHED_VERSION="$(rpc /v1/chain/get_producer_schedule '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["active"]["version"])')"
H=$(( $(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])') + 60 ))
echo "cutover-voter-test: init H=$H, freezing the one-member schedule (version $SCHED_VERSION)..."
mk_push raw "$CHAIN_ID" "$DEV_WIF" cutover init cutover \
    "$(python3 - "$H" "$CHAIN_ID" "$SCHED_VERSION" "eosio" "$PUB33" <<'PYEOF'
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
def name_to_u64(s):
    charmap = ".12345abcdefghijklmnopqrstuvwxyz"
    def sym(c):
        if "a" <= c <= "z":
            return ord(c) - ord("a") + 6
        if "1" <= c <= "5":
            return ord(c) - ord("1") + 1
        return 0
    v = 0
    for i in range(12):
        v = (v << 5) | sym(s[i] if i < len(s) else ".")
    return (v << 4) | (sym(s[12]) if len(s) == 13 else 0)
out = bytearray(struct.pack("<I", int(sys.argv[1])) + bytes.fromhex(sys.argv[2]) + struct.pack("<I", int(sys.argv[3])))
out += varuint(1) + struct.pack("<Q", name_to_u64(sys.argv[4])) + varuint(0) + bytes.fromhex(sys.argv[5])
print(bytes(out).hex())
PYEOF
)" >/dev/null
FROZEN_DIGEST="$(table_rows cutover cutover ceremony | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["declaration_digest"])')"
[[ -n "$FROZEN_DIGEST" ]] || fail "no frozen ceremony"
pass "ceremony frozen at H=$H"

# (4) proves the opt-in producer stop: half-configured stop fails fast,
# dry-run rehearses the pause, a live pause lands after confirmation and is
# re-asserted on later polls (continuous enforcement), and an unverified
# pause fails loud instead of going quiet.

# Voter key files must be owner-only or the voter refuses to start.
printf '%s' "$DEV_WIF" >"$WORK/vote.key"; chmod 600 "$WORK/vote.key"
printf '%s' "$DEV_WIF" >"$WORK/payer.key"; chmod 600 "$WORK/payer.key"
# The roster mirrors the frozen on-chain member row byte-for-byte (whatever
# string form the node renders): the recomputed digest must equal the
# frozen one, or the voter refuses to sign.
table_rows cutover cutover members \
    | python3 -c 'import json,sys; print(json.dumps([{"producer":r["producer"],"key":r["key"],"weight":r["weight"]} for r in json.load(sys.stdin)]))' \
    >"$WORK/roster.json"

# The migration genesis this voter will sign: it pins the checkpoint hash the
# voter configures as its own and the hash of the one-member source schedule
# (the published-schedule pin), and its ceremony chain id is what the
# coordinator must serve. The voter signs only a genesis it has read.
HALT_BIN="$REPO_ROOT/target/debug/examples/xpr_halt_ceremony"
GENESIS="$WORK/migration-genesis.json"
python3 - "$REPO_ROOT/tools/xpr-chainbase-export/localnet/genesis.json" "$GENESIS" "$SCHED_VERSION" "$PUB33" <<'PYEOF'
import hashlib, json, struct, sys
src, out, version, pub33 = sys.argv[1], sys.argv[2], int(sys.argv[3]), bytes.fromhex(sys.argv[4])
CHARMAP = ".12345abcdefghijklmnopqrstuvwxyz"
def name_u64(text):
    value = 0
    for i in range(12):
        c = CHARMAP.index(text[i]) if i < len(text) else 0
        value |= (c & 0x1f) << (64 - 5 * (i + 1))
    if len(text) > 12:
        value |= CHARMAP.index(text[12]) & 0x0f
    return value
packed = struct.pack("<I", version) + bytes([1]) + struct.pack("<Q", name_u64("eosio"))
packed += bytes([0]) + struct.pack("<I", 1) + bytes([1]) + bytes([0]) + pub33 + struct.pack("<H", 1)
genesis = json.load(open(src))
genesis["migration_checkpoint_sha256"] = "ab" * 32
genesis["migration_schedule_sha256"] = hashlib.sha256(packed).hexdigest()
json.dump(genesis, open(out, "w"))
PYEOF
NEW_CHAIN="$("$HALT_BIN" chain-id --genesis "$GENESIS")"
# The published schedule hash is a pre-H config field, known before the genesis.
SCHEDULE_SHA256="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["migration_schedule_sha256"])' "$GENESIS")"
PLATFORM="$(python3 -c 'print("ee" * 32)')"
WRONG_PLATFORM="$(python3 -c 'print("ef" * 32)')"
# Agreed pause head P = H + PAUSE_K, fixed before the freeze like on mainnet.
PAUSE_K=20
# $6=OPFED starts the voter as the ceremony agent does before H: no checkpoint
# hash, genesis or platform id yet. CFG_SCHEDULE overrides the published pin.
mk_config() { # $1=height $2=dry $3=coord-url-or-empty $4=platform-or-empty $5=stop-url-or-HALF-or-empty $6=OPFED-or-empty -> path
    local out="$WORK/voter-$RANDOM.json"
    local coord="null"
    [[ -n "${3:-}" ]] && coord="\"$3\""
    local plat="\"$PLATFORM\""   # the platform id is mandatory config: never adopted
    [[ -n "${4:-}" ]] && plat="\"$4\""
    local stop='"stop_producer":{"at_pause":false}'
    if [[ "${5:-}" == "HALF" ]]; then
        stop='"stop_producer":{"at_pause":true}'
    elif [[ -n "${5:-}" ]]; then
        stop="\"stop_producer\":{\"at_pause\":true,\"producer_api_url\":\"$5\"}"
    fi
    local confirmation_inputs="\"migration_genesis\":\"$GENESIS\",\"checkpoint_sha256\":\"abababababababababababababababababababababababababababababababab\",\"platform_chain_id\":$plat"
    if [[ "${6:-}" == "OPFED" ]]; then
        confirmation_inputs="\"operator_fed\":true"
    fi
    cat >"$out" <<EOF
{"nodeos_url":"http://127.0.0.1:${PORT}","contract":"cutover","producer":"eosio",
 "source_chain_id":"$CHAIN_ID","height":$1,"pause_height":$(($1 + PAUSE_K)),"schedule_version":$SCHED_VERSION,"roster_file":"$WORK/roster.json",
 "vote_key_file":"$WORK/vote.key","payer_account":"eosio","payer_key_file":"$WORK/payer.key",
 "poll_secs":1,"dry_run":$2,"enabled":true,
 "confirmation":{"coordinator_url":$coord,"out_file":"$WORK/confirmation.json",
  "schedule_sha256":"${CFG_SCHEDULE:-$SCHEDULE_SHA256}",$confirmation_inputs},
 $stop}
EOF
    printf '%s' "$out"
}

echo "cutover-voter-test: dry-run refuses a foreign freeze without signing..."
WRONG_CFG="$(mk_config $((H + 50)) true "")"
if "$VOTER_BIN" --config "$WRONG_CFG" --dry-run --max-polls 3 >"$WORK/dry.log" 2>&1; then
    grep -q "refusing" "$WORK/dry.log" || fail "dry-run did not explain the refusal: $(cat "$WORK/dry.log")"
else
    fail "dry-run with max-polls must exit 0: $(cat "$WORK/dry.log")"
fi
echo "cutover-voter-test: members row: $(table_rows cutover cutover members)"
VOTED="$(table_rows cutover cutover members | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["voted"])')"
[[ "$VOTED" == "False" || "$VOTED" == "0" ]] || fail "dry-run submitted a vote (voted=$VOTED)"
pass "foreign freeze refused, nothing signed"

echo "cutover-voter-test: print-digest exposes the exact signing digest..."
PRINT_CFG="$(mk_config "$H" true "" "$PLATFORM")"
"$VOTER_BIN" --config "$PRINT_CFG" --print-digest >"$WORK/digest.json" 2>"$WORK/digest.err" \
    || fail "print-digest failed: $(cat "$WORK/digest.err")"
python3 - "$WORK/digest.json" "$FROZEN_DIGEST" <<'PYEOF'
import json, sys
shape = json.load(open(sys.argv[1]))
want = sys.argv[2]
assert shape["role"] == "declaration", shape
assert shape["producer"] == "eosio", shape
assert shape["digest"] == want, (shape["digest"], want)
PYEOF
pass "print-digest matches the frozen declaration digest"

echo "cutover-voter-test: preflight gives GO on a ready operator..."
PREFLIGHT_CFG="$(mk_config "$H" true "" "$PLATFORM")"
"$VOTER_BIN" --config "$PREFLIGHT_CFG" --preflight >"$WORK/preflight.log" 2>&1 \
    || fail "preflight refused a ready setup: $(cat "$WORK/preflight.log")"
grep -q "PREFLIGHT: GO" "$WORK/preflight.log" || fail "no preflight GO: $(cat "$WORK/preflight.log")"
grep -q "freeze on-chain" "$WORK/preflight.log" || fail "preflight skipped the freeze check"
pass "preflight GO before the window"

echo "cutover-voter-test: an operator-fed voter starts before H and preflight says WAIT..."
FED_CFG="$(mk_config "$H" true "" "" "" OPFED)"
"$VOTER_BIN" --config "$FED_CFG" --preflight >"$WORK/preflight-fed.log" 2>&1 \
    || fail "preflight refused an operator-fed config before H: $(cat "$WORK/preflight-fed.log")"
grep -q "PREFLIGHT WAIT: confirmation inputs" "$WORK/preflight-fed.log" \
    || fail "preflight did not WAIT on the post-H inputs: $(cat "$WORK/preflight-fed.log")"
grep -q "PREFLIGHT: GO" "$WORK/preflight-fed.log" \
    || fail "operator-fed preflight is not GO before H: $(cat "$WORK/preflight-fed.log")"
# Without the opt-in the same config can never sign and refuses to load.
sed 's/"operator_fed":true/"operator_fed":false/' "$FED_CFG" >"$WORK/not-fed.json"
if "$VOTER_BIN" --config "$WORK/not-fed.json" --preflight >"$WORK/not-fed.log" 2>&1; then
    fail "a config without the post-H inputs loaded without operator_fed: $(cat "$WORK/not-fed.log")"
fi
grep -q "operator_fed" "$WORK/not-fed.log" || fail "refusal does not name operator_fed: $(cat "$WORK/not-fed.log")"
pass "operator-fed voter loads and preflights before H; a config that can never sign still refuses"

echo "cutover-voter-test: preflight refuses a stop window inside the finality lag..."
SHORT_CFG="$WORK/voter-short-window.json"
python3 -I - "$PREFLIGHT_CFG" "$SHORT_CFG" "$H" <<'PYEOF'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg["pause_height"] = int(sys.argv[3]) + 1
json.dump(cfg, open(sys.argv[2], "w"))
PYEOF
if "$VOTER_BIN" --config "$SHORT_CFG" --preflight >"$WORK/preflight-short.log" 2>&1; then
    fail "preflight accepted a stop window inside the finality lag: $(cat "$WORK/preflight-short.log")"
fi
grep -q "PREFLIGHT FAIL: stop window past finality" "$WORK/preflight-short.log" \
    || fail "short stop window not named in the refusal: $(cat "$WORK/preflight-short.log")"
grep -q "PREFLIGHT: NO-GO" "$WORK/preflight-short.log" || fail "short stop window did not produce NO-GO"
grep -q "stop window past finality" "$WORK/preflight.log" || fail "GO preflight skipped the stop-window check"
pass "preflight refuses a stop window shorter than the finality lag"

# The producer API check runs against the REAL nodeos producer API of the
# throwaway node (read-only: it only asks paused, it never pauses the chain).
# Leap 5.0.3 answers with a bare boolean; the stubs elsewhere in this script
# also answer that way.
echo "cutover-voter-test: preflight reads the real producer API's paused reply..."
REAL_API_CFG="$(mk_config "$H" true "" "$PLATFORM" "$API")"
"$VOTER_BIN" --config "$REAL_API_CFG" --preflight >"$WORK/preflight-real-api.log" 2>&1 \
    || fail "preflight against the real producer API failed: $(cat "$WORK/preflight-real-api.log")"
grep -q "producer api reachable: paused=false" "$WORK/preflight-real-api.log" \
    || fail "the real producer API's paused reply was not read: $(cat "$WORK/preflight-real-api.log")"
pass "preflight parses the real producer API's paused reply"

# A stale schedule pin must abort before H, while nothing has been paused.
echo "cutover-voter-test: a stale schedule pin aborts the voter before H..."
CFG_SCHEDULE="$(python3 -c 'print("22" * 32)')"
STALE_CFG="$(mk_config "$H" true "" "" "" OPFED)"
unset CFG_SCHEDULE
if "$VOTER_BIN" --config "$STALE_CFG" --dry-run --max-polls 3 >"$WORK/stale-pin.log" 2>&1; then
    fail "the voter ran on a stale schedule pin: $(cat "$WORK/stale-pin.log")"
fi
grep -q "no longer hashes to confirmation.schedule_sha256" "$WORK/stale-pin.log" \
    || fail "stale pin not reported: $(cat "$WORK/stale-pin.log")"
grep -q "ALARM event=cutover.schedule_pin_abort" "$WORK/stale-pin.log" \
    || fail "stale pin raised no alarm line: $(cat "$WORK/stale-pin.log")"
set +e
"$VOTER_BIN" --config "$STALE_CFG" --dry-run --max-polls 3 >/dev/null 2>&1
STALE_EXIT=$?
set -e
[[ "$STALE_EXIT" == 3 ]] || fail "stale pin exit code is $STALE_EXIT, not the distinct abort code 3"
# The same stale pin fails the operator's preflight too.
if "$VOTER_BIN" --config "$STALE_CFG" --preflight >"$WORK/stale-pin-preflight.log" 2>&1; then
    fail "preflight accepted a stale schedule pin: $(cat "$WORK/stale-pin-preflight.log")"
fi
grep -q "PREFLIGHT FAIL: schedule pin" "$WORK/stale-pin-preflight.log" \
    || fail "preflight did not flag the stale pin: $(cat "$WORK/stale-pin-preflight.log")"
pass "a stale schedule pin aborts before H and fails preflight"

echo "cutover-voter-test: status reports the loop state as JSON..."
"$VOTER_BIN" --config "$PREFLIGHT_CFG" --status >"$WORK/status.json" 2>"$WORK/status.err" \
    || fail "status failed: $(cat "$WORK/status.err")"
python3 - "$WORK/status.json" "$H" <<'PYEOF'
import json, sys
st = json.load(open(sys.argv[1]))
assert st["producer"] == "eosio", st
assert st["height"] == int(sys.argv[2]), st
assert st["vote"] in ("pending", "on-chain"), st
assert st["freeze_match"] is True, st
assert st["schedule_blocked"] is False, st
assert st["pause"] == "off", st
PYEOF
pass "status JSON matches the on-chain freeze"

# Coordinator serving live chain data: block id is read from the node itself,
# so it always matches; the voter must still verify every field.
cat >"$WORK/coordinator.py" <<'PYEOF'
import json, sys, urllib.request
node, mode, out = sys.argv[1], sys.argv[2], sys.argv[3]
plat = sys.argv[6]
def rpc(path, body):
    req = urllib.request.Request(node + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Host": "0.0.0.0:8888"})
    return json.load(urllib.request.urlopen(req, timeout=20))
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        info = rpc("/v1/chain/get_info", {})
        h = int(self.path.rsplit("=", 1)[-1]) if "=" in self.path else H_PLACEHOLDER
        blk = rpc("/v1/chain/get_block", {"block_num_or_id": str(h)})
        body = {"halt_height": h, "halt_block_id": blk["id"] if mode in ("good", "bad-platform") else "00" * 32,
                "checkpoint_sha256": "ab" * 32, "new_chain_id": sys.argv[7],
                "platform_chain_id": plat,
                "source_chain_id": info["chain_id"]}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(ln)
        open(out, "ab").write(payload + b"\n")
        data = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
H_PLACEHOLDER = int(sys.argv[4])
PORT_FILE = sys.argv[5]
server = HTTPServer(("127.0.0.1", 0), H)
with open(PORT_FILE, "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
PYEOF
echo "cutover-voter-test: live vote plus coordinator confirmation..."
python3 "$WORK/coordinator.py" "$API" good "$WORK/confirmations.jsonl" "$H" "$WORK/coord.port" "$PLATFORM" "$NEW_CHAIN" >>"$WORK/coordinator.log" 2>&1 &
COORD_PID=$!
for _ in $(seq 1 30); do
    [[ -s "$WORK/coord.port" ]] && break
    kill -0 "$COORD_PID" 2>/dev/null || fail "coordinator died on startup: $(cat "$WORK/coordinator.log")"
    sleep 1
done
COORD_PORT="$(cat "$WORK/coord.port")"
LIVE_CFG="$(mk_config "$H" false "http://127.0.0.1:${COORD_PORT}" "$PLATFORM")"
# Portable timeout (no GNU timeout on macOS): background the voter, wait for
# its log to show delivery, kill on expiry.
"$VOTER_BIN" --config "$LIVE_CFG" >"$WORK/live.log" 2>&1 &
VOTER_PID=$!
VOTER_DONE=""
for _ in $(seq 1 90); do
    grep -q "delivered to coordinator" "$WORK/live.log" 2>/dev/null && { VOTER_DONE=1; break; }
    kill -0 "$VOTER_PID" 2>/dev/null || break
    sleep 2
done
if [[ -z "$VOTER_DONE" ]]; then
    kill "$VOTER_PID" 2>/dev/null || true
    wait "$VOTER_PID" 2>/dev/null || true
    fail "voter did not deliver within 180s, first lines: $(head -8 "$WORK/live.log" | tr '\n' '|')"
fi
kill "$VOTER_PID" 2>/dev/null || true
wait "$VOTER_PID" 2>/dev/null || true
kill "$COORD_PID" 2>/dev/null || true
wait "$COORD_PID" 2>/dev/null || true
grep -q "vote submitted" "$WORK/live.log" || fail "no vote submitted: $(tail -5 "$WORK/live.log")"
VOTED="$(table_rows cutover cutover members | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["voted"])')"
[[ "$VOTED" == "True" || "$VOTED" == "true" || "$VOTED" == "1" ]] || fail "vote did not land on-chain (voted=$VOTED)"
grep -q "delivered to coordinator" "$WORK/live.log" || fail "no confirmation delivered"
python3 - "$WORK/confirmations.jsonl" "$PLATFORM" "$H" <<'PYEOF'
import json, sys
conf = [json.loads(line) for line in open(sys.argv[1]) if line.strip()][-1]
assert conf["producer"] == "eosio", conf
assert conf["platform_chain_id"] == sys.argv[2], conf
assert isinstance(conf["pause_height"], int) and conf["pause_height"] >= int(sys.argv[3]), conf
assert len(conf["pause_block_id"]) == 64 and int(conf["pause_block_id"], 16) >= 0, conf
PYEOF
pass "vote landed and platform-bound confirmation delivered unattended"

echo "cutover-voter-test: lying coordinator is refused..."
python3 "$WORK/coordinator.py" "$API" bad "$WORK/confirmations-bad.jsonl" "$H" "$WORK/coord-bad.port" "$PLATFORM" "$NEW_CHAIN" >>"$WORK/coordinator-bad.log" 2>&1 &
COORD_PID=$!
for _ in $(seq 1 30); do
    [[ -s "$WORK/coord-bad.port" ]] && break
    kill -0 "$COORD_PID" 2>/dev/null || fail "bad coordinator died on startup: $(cat "$WORK/coordinator-bad.log")"
    sleep 1
done
COORD_BAD_PORT="$(cat "$WORK/coord-bad.port")"
BAD_CFG="$(mk_config "$H" false "http://127.0.0.1:${COORD_BAD_PORT}")"
# The vote is already on-chain, so the voter heads straight for the
# confirmation, which must fail closed on the mismatched block id.
"$VOTER_BIN" --config "$BAD_CFG" --max-polls 16 >"$WORK/bad.log" 2>&1 &
BAD_PID=$!
for _ in $(seq 1 15); do
    kill -0 "$BAD_PID" 2>/dev/null || break
    sleep 2
done
kill "$BAD_PID" 2>/dev/null || true
wait "$BAD_PID" 2>/dev/null || true
kill "$COORD_PID" 2>/dev/null || true
wait "$COORD_PID" 2>/dev/null || true
grep -q "does not match this node" "$WORK/bad.log" || fail "lying coordinator not refused: $(tail -5 "$WORK/bad.log")"
[[ -s "$WORK/confirmations-bad.jsonl" ]] && fail "confirmation delivered to lying coordinator"
pass "lying coordinator refused, nothing delivered"

echo "cutover-voter-test: coordinator serving a different platform id is refused..."
python3 "$WORK/coordinator.py" "$API" bad-platform "$WORK/confirmations-wrongplat.jsonl" "$H" "$WORK/coord-plat.port" "$WRONG_PLATFORM" "$NEW_CHAIN" >>"$WORK/coordinator-plat.log" 2>&1 &
COORD_PID=$!
for _ in $(seq 1 30); do
    [[ -s "$WORK/coord-plat.port" ]] && break
    kill -0 "$COORD_PID" 2>/dev/null || fail "platform coordinator died on startup: $(cat "$WORK/coordinator-plat.log")"
    sleep 1
done
COORD_PLAT_PORT="$(cat "$WORK/coord-plat.port")"
PLAT_CFG="$(mk_config "$H" false "http://127.0.0.1:${COORD_PLAT_PORT}" "$PLATFORM")"
"$VOTER_BIN" --config "$PLAT_CFG" --max-polls 16 >"$WORK/plat.log" 2>&1 &
PLAT_PID=$!
for _ in $(seq 1 15); do
    kill -0 "$PLAT_PID" 2>/dev/null || break
    sleep 2
done
kill "$PLAT_PID" 2>/dev/null || true
wait "$PLAT_PID" 2>/dev/null || true
kill "$COORD_PID" 2>/dev/null || true
wait "$COORD_PID" 2>/dev/null || true
grep -q "platform chain id does not match" "$WORK/plat.log" || fail "wrong platform not refused: $(tail -5 "$WORK/plat.log")"
[[ -s "$WORK/confirmations-wrongplat.jsonl" ]] && fail "confirmation delivered to wrong-platform coordinator"
pass "wrong platform refused, nothing delivered"

# The voter signs only a genesis it has read: one that pins a checkpoint it did
# not derive, or a schedule hash the live committee does not match, is refused
# and nothing is delivered.
echo "cutover-voter-test: a genesis pinning a foreign checkpoint or a wrong schedule is refused..."
python3 - "$GENESIS" "$WORK/genesis-foreign-checkpoint.json" "$WORK/genesis-wrong-schedule.json" <<'PYEOF'
import json, sys
src = json.load(open(sys.argv[1]))
foreign = dict(src); foreign["migration_checkpoint_sha256"] = "cc" * 32
wrong = dict(src); wrong["migration_schedule_sha256"] = "11" * 32
json.dump(foreign, open(sys.argv[2], "w"))
json.dump(wrong, open(sys.argv[3], "w"))
PYEOF
GOOD_GENESIS="$GENESIS"
run_refused_genesis() { # $1=genesis file $2=log name $3=expected substring $4=coordinator chain id
    local cfg coord_pid port_file="$WORK/coord-$2.port"
    rm -f "$port_file" "$WORK/confirmations-$2.jsonl"
    python3 "$WORK/coordinator.py" "$API" good "$WORK/confirmations-$2.jsonl" "$H" "$port_file" "$PLATFORM" "$4" >>"$WORK/coordinator-$2.log" 2>&1 &
    coord_pid=$!
    for _ in $(seq 1 30); do
        [[ -s "$port_file" ]] && break
        kill -0 "$coord_pid" 2>/dev/null || fail "coordinator ($2) died on startup: $(cat "$WORK/coordinator-$2.log")"
        sleep 1
    done
    GENESIS="$1"
    cfg="$(mk_config "$H" false "http://127.0.0.1:$(cat "$port_file")" "$PLATFORM")"
    GENESIS="$GOOD_GENESIS"
    "$VOTER_BIN" --config "$cfg" --max-polls 16 >"$WORK/$2.log" 2>&1 &
    local vpid=$!
    for _ in $(seq 1 30); do
        kill -0 "$vpid" 2>/dev/null || break
        sleep 2
    done
    kill "$vpid" 2>/dev/null || true
    wait "$vpid" 2>/dev/null || true
    kill "$coord_pid" 2>/dev/null || true
    wait "$coord_pid" 2>/dev/null || true
    grep -q "$3" "$WORK/$2.log" || fail "$2 not refused ($3): $(tail -5 "$WORK/$2.log")"
    [[ -s "$WORK/confirmations-$2.jsonl" ]] && fail "confirmation delivered despite $2"
    return 0
}
run_refused_genesis "$WORK/genesis-foreign-checkpoint.json" foreigncp "did not derive" "$NEW_CHAIN"
WRONG_SCHEDULE_CHAIN="$("$HALT_BIN" chain-id --genesis "$WORK/genesis-wrong-schedule.json")"
run_refused_genesis "$WORK/genesis-wrong-schedule.json" wrongsched "not told to expect" "$WRONG_SCHEDULE_CHAIN"
pass "foreign checkpoint pin and wrong schedule pin refused, nothing delivered"

echo "cutover-voter-test: half-configured stop fails fast..."
HALF_CFG="$(mk_config "$H" true "" "" HALF)"
if "$VOTER_BIN" --config "$HALF_CFG" --max-polls 1 >"$WORK/half.log" 2>&1; then
    fail "half-configured stop started: $(cat "$WORK/half.log")"
fi
grep -q "cannot fire" "$WORK/half.log" || fail "half-config refusal unexplained: $(cat "$WORK/half.log")"
pass "half-configured stop fails fast"

# Stub Leap producer API: pause always succeeds, paused reports the argv
# value. Hits are recorded so the test proves calls happened, not just logs.
cat >"$WORK/stub-producer.py" <<'PYEOF'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
paused_value = sys.argv[1]
hits_path, port_path = sys.argv[2], sys.argv[3]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0))
        self.rfile.read(ln)
        if self.path.endswith("/v1/producer/pause"):
            open(hits_path, "a").write("pause\n")
            data = b"{}"
        elif self.path.endswith("/v1/producer/paused"):
            # Leap 5.0.3 answers with a bare boolean, not an object.
            data = paused_value.encode()
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
server = HTTPServer(("127.0.0.1", 0), H)
open(port_path, "w").write(str(server.server_address[1]))
server.serve_forever()
PYEOF
start_stub() { # $1=true|false $2=hits-file $3=port-file -> pid in STUB_PID
    python3 "$WORK/stub-producer.py" "$1" "$2" "$3" >>"$WORK/stub.log" 2>&1 &
    STUB_PID=$!
    for _ in $(seq 1 30); do
        [[ -s "$3" ]] && break
        kill -0 "$STUB_PID" 2>/dev/null || fail "producer stub died on startup: $(cat "$WORK/stub.log")"
        sleep 1
    done
}

echo "cutover-voter-test: a foreign finalized ceremony never arms the pause..."
# H=5 names a ceremony this voter did not declare (the on-chain one is for a
# different height and digest). Even though the singleton is finalized and the
# head is long past this config's P, nothing may be armed or announced.
PAST_CFG="$(mk_config 5 true "" "" "http://127.0.0.1:9")"
"$VOTER_BIN" --config "$PAST_CFG" --dry-run --max-polls 3 >"$WORK/pausedry.log" 2>&1 \
    || fail "dry-run on a foreign ceremony failed: $(cat "$WORK/pausedry.log")"
! grep -q "would pause" "$WORK/pausedry.log" \
    || fail "a foreign finalized ceremony armed the pause: $(cat "$WORK/pausedry.log")"
grep -q "refusing: ceremony height" "$WORK/pausedry.log" \
    || fail "foreign ceremony was not refused: $(cat "$WORK/pausedry.log")"
pass "a foreign finalized ceremony never arms the pause"

echo "cutover-voter-test: dry-run rehearses the producer pause for our own ceremony..."
for _ in $(seq 1 120); do
    HEAD_NOW="$(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])')"
    [[ "$HEAD_NOW" -ge $((H + PAUSE_K)) ]] && break
    sleep 1
done
OWN_CFG="$(mk_config "$H" true "" "" "http://127.0.0.1:9")"
"$VOTER_BIN" --config "$OWN_CFG" --dry-run --max-polls 3 >"$WORK/pausedry-own.log" 2>&1 \
    || fail "dry-run pause rehearsal failed: $(cat "$WORK/pausedry-own.log")"
grep -q "would pause the local producer at P=$((H + PAUSE_K))" "$WORK/pausedry-own.log" \
    || fail "no dry-run pause line: $(cat "$WORK/pausedry-own.log")"
pass "dry-run rehearses the producer pause"

echo "cutover-voter-test: live pause after confirmation, enforced continuously..."
start_stub true "$WORK/pause-hits" "$WORK/stub.port"
STUB_PORT="$(cat "$WORK/stub.port")"
python3 "$WORK/coordinator.py" "$API" good "$WORK/confirmations-pause.jsonl" "$H" "$WORK/coord-pause.port" "$PLATFORM" "$NEW_CHAIN" >>"$WORK/coordinator-pause.log" 2>&1 &
COORD_PID=$!
for _ in $(seq 1 30); do
    [[ -s "$WORK/coord-pause.port" ]] && break
    kill -0 "$COORD_PID" 2>/dev/null || fail "pause coordinator died on startup"
    sleep 1
done
COORD_PAUSE_PORT="$(cat "$WORK/coord-pause.port")"
PAUSE_CFG="$(mk_config "$H" false "http://127.0.0.1:${COORD_PAUSE_PORT}" "$PLATFORM" "http://127.0.0.1:${STUB_PORT}")"
"$VOTER_BIN" --config "$PAUSE_CFG" >"$WORK/pause.log" 2>&1 &
PAUSE_PID=$!
PAUSED=""
for _ in $(seq 1 90); do
    grep -q "local producer paused at P=" "$WORK/pause.log" 2>/dev/null && { PAUSED=1; break; }
    kill -0 "$PAUSE_PID" 2>/dev/null || break
    sleep 2
done
[[ -n "$PAUSED" ]] || { kill "$PAUSE_PID" 2>/dev/null || true; wait "$PAUSE_PID" 2>/dev/null || true; fail "producer never paused: $(tail -5 "$WORK/pause.log")"; }
# Continuous enforcement: the voter must re-assert the pause on later polls,
# not exit after the first one (a node restart clears Leap's in-memory pause).
REENFORCED=""
for _ in $(seq 1 15); do
    [[ "$(wc -l <"$WORK/pause-hits" 2>/dev/null || echo 0)" -ge 2 ]] && { REENFORCED=1; break; }
    sleep 2
done
kill "$PAUSE_PID" 2>/dev/null || true
wait "$PAUSE_PID" 2>/dev/null || true
kill "$STUB_PID" 2>/dev/null || true
wait "$STUB_PID" 2>/dev/null || true
kill "$COORD_PID" 2>/dev/null || true
wait "$COORD_PID" 2>/dev/null || true
[[ -n "$REENFORCED" ]] || fail "pause asserted only once, not enforced: $(cat "$WORK/pause-hits" 2>/dev/null)"
pass "producer paused after confirmation and re-asserted"

echo "cutover-voter-test: the pause never waits on the post-H inputs..."
start_stub true "$WORK/fed-hits" "$WORK/stub-fed.port"
FEDSTUB_PORT="$(cat "$WORK/stub-fed.port")"
FEDPAUSE_CFG="$(mk_config "$H" false "" "" "http://127.0.0.1:${FEDSTUB_PORT}" OPFED)"
"$VOTER_BIN" --config "$FEDPAUSE_CFG" >"$WORK/fed-pause.log" 2>&1 &
FEDPAUSE_PID=$!
FEDPAUSED=""
for _ in $(seq 1 60); do
    grep -q "local producer paused at P=" "$WORK/fed-pause.log" 2>/dev/null && { FEDPAUSED=1; break; }
    kill -0 "$FEDPAUSE_PID" 2>/dev/null || break
    sleep 2
done
FEDBLOCKED=""
for _ in $(seq 1 15); do
    grep -q "signing blocked" "$WORK/fed-pause.log" 2>/dev/null && { FEDBLOCKED=1; break; }
    sleep 2
done
kill "$FEDPAUSE_PID" 2>/dev/null || true
wait "$FEDPAUSE_PID" 2>/dev/null || true
kill "$STUB_PID" 2>/dev/null || true
wait "$STUB_PID" 2>/dev/null || true
[[ -n "$FEDPAUSED" ]] || fail "operator-fed voter never paused: $(tail -5 "$WORK/fed-pause.log")"
[[ -n "$FEDBLOCKED" ]] || fail "operator-fed voter did not report signing blocked: $(tail -5 "$WORK/fed-pause.log")"
pass "an operator-fed voter pauses at P and reports signing blocked until the inputs land"

echo "cutover-voter-test: the whole operator flow: start fed-empty, pause, feed a bad value, feed the good ones, sign..."
# The ceremony agent's real order after H. The same chain, one voter config
# edited between restarts the way the agent edits it.
feed_config() { # $1=base config $2=checkpoint $3=coordinator url or empty -> new config path
    local out="$WORK/voter-fed-$RANDOM.json"
    python3 - "$1" "$out" "$2" "${3:-}" "$GENESIS" "$PLATFORM" <<'PYEOF'
import json, sys
src, out, checkpoint, coord, genesis, platform = sys.argv[1:7]
cfg = json.load(open(src))
conf = cfg["confirmation"]
conf["checkpoint_sha256"] = checkpoint
conf["migration_genesis"] = genesis
conf["platform_chain_id"] = platform
if coord:
    conf["coordinator_url"] = coord
json.dump(cfg, open(out, "w"))
PYEOF
    printf '%s' "$out"
}
wait_for_log() { # $1=file $2=pattern $3=pid $4=tries
    for _ in $(seq 1 "$4"); do
        grep -q "$2" "$1" 2>/dev/null && return 0
        kill -0 "$3" 2>/dev/null || return 1
        sleep 2
    done
    return 1
}
start_stub true "$WORK/flow-hits" "$WORK/stub-flow.port"
FLOWSTUB_PORT="$(cat "$WORK/stub-flow.port")"
FLOW_BASE="$(mk_config "$H" false "" "" "http://127.0.0.1:${FLOWSTUB_PORT}" OPFED)"
rm -f "$FLOW_BASE.finalized"
# 1. Nothing fed: pauses, blocks signing.
"$VOTER_BIN" --config "$FLOW_BASE" >"$WORK/flow-1.log" 2>&1 &
FLOW_PID=$!
wait_for_log "$WORK/flow-1.log" "local producer paused at P=" "$FLOW_PID" 60 || fail "flow 1: no pause: $(tail -5 "$WORK/flow-1.log")"
wait_for_log "$WORK/flow-1.log" "signing blocked" "$FLOW_PID" 15 || fail "flow 1: signing not reported blocked: $(tail -5 "$WORK/flow-1.log")"
kill "$FLOW_PID" 2>/dev/null || true; wait "$FLOW_PID" 2>/dev/null || true
[[ -s "$FLOW_BASE.finalized" ]] || fail "flow 1: finalization marker was not written next to the config"
# 2. A bad checkpoint is fed after H: the voter must keep enforcing the pause
# and refuse to sign, not exit.
BAD_FLOW="$(feed_config "$FLOW_BASE" "$(python3 -c 'print("cd" * 32)')" "")"
cp "$FLOW_BASE.finalized" "$BAD_FLOW.finalized"
"$VOTER_BIN" --config "$BAD_FLOW" >"$WORK/flow-2.log" 2>&1 &
FLOW_PID=$!
wait_for_log "$WORK/flow-2.log" "local producer paused at P=" "$FLOW_PID" 60 || fail "flow 2: a bad fed value ended pause enforcement: $(tail -5 "$WORK/flow-2.log")"
sleep 6
kill -0 "$FLOW_PID" 2>/dev/null || fail "flow 2: the voter exited on a bad fed value: $(tail -5 "$WORK/flow-2.log")"
grep -q "ALARM event=cutover.signing_inputs_invalid" "$WORK/flow-2.log" || fail "flow 2: no alarm for the bad fed value: $(head -5 "$WORK/flow-2.log")"
grep -q "did not derive" "$WORK/flow-2.log" || fail "flow 2: the bad value was not named: $(head -5 "$WORK/flow-2.log")"
! grep -q "delivered to coordinator" "$WORK/flow-2.log" || fail "flow 2: the voter signed with a bad fed value"
kill "$FLOW_PID" 2>/dev/null || true; wait "$FLOW_PID" 2>/dev/null || true
# 3. The good values land: the restarted voter signs and delivers. The marker
# from run 1 restores finalization before any chain read.
python3 "$WORK/coordinator.py" "$API" good "$WORK/confirmations-flow.jsonl" "$H" "$WORK/coord-flow.port" "$PLATFORM" "$NEW_CHAIN" >>"$WORK/coordinator-flow.log" 2>&1 &
COORD_PID=$!
for _ in $(seq 1 30); do [[ -s "$WORK/coord-flow.port" ]] && break; sleep 1; done
GOOD_FLOW="$(feed_config "$FLOW_BASE" "$(python3 -c 'print("ab" * 32)')" "http://127.0.0.1:$(cat "$WORK/coord-flow.port")")"
cp "$FLOW_BASE.finalized" "$GOOD_FLOW.finalized"
"$VOTER_BIN" --config "$GOOD_FLOW" >"$WORK/flow-3.log" 2>&1 &
FLOW_PID=$!
wait_for_log "$WORK/flow-3.log" "delivered to coordinator" "$FLOW_PID" 90 || fail "flow 3: no signature after the good values were fed: $(tail -8 "$WORK/flow-3.log")"
kill "$FLOW_PID" 2>/dev/null || true; wait "$FLOW_PID" 2>/dev/null || true
kill "$COORD_PID" 2>/dev/null || true; wait "$COORD_PID" 2>/dev/null || true
kill "$STUB_PID" 2>/dev/null || true; wait "$STUB_PID" 2>/dev/null || true
grep -q "ceremony finalization restored" "$WORK/flow-3.log" || fail "flow 3: the restart did not restore finalization from the marker"
pass "operator flow: fed-empty pause, bad fed value blocks signing but keeps the pause, good values sign after a restart"

echo "cutover-voter-test: a config that stops loading keeps the pause; enabled=false still stops it..."
# After P the pause is the whole point: a voter that exits because its config
# became unreadable lets the next nodeos restart resume block production. With
# a recorded round it must keep pausing from the record and sign nothing.
start_stub true "$WORK/deg-hits" "$WORK/stub-deg.port"
DEG_PORT="$(cat "$WORK/stub-deg.port")"
DEG_CFG="$WORK/voter-degraded.json"
cp "$FLOW_BASE" "$DEG_CFG"
python3 - "$FLOW_BASE.finalized" "$DEG_CFG.finalized" "$DEG_PORT" <<'PYEOF'
import json, sys
state = json.load(open(sys.argv[1]))
assert state["format"] == 1 and state["pause_height"] > state["height"], state
state["producer_api_url"] = f"http://127.0.0.1:{sys.argv[3]}"
json.dump(state, open(sys.argv[2], "w"))
PYEOF
: > "$DEG_CFG"   # truncated: not parseable
"$VOTER_BIN" --config "$DEG_CFG" >"$WORK/deg.log" 2>&1 &
DEG_PID=$!
wait_for_log "$WORK/deg.log" "from the recorded state" "$DEG_PID" 40 || fail "degraded voter did not pause from the record: $(tail -5 "$WORK/deg.log")"
kill -0 "$DEG_PID" 2>/dev/null || fail "degraded voter exited instead of holding the pause: $(tail -5 "$WORK/deg.log")"
grep -q "ALARM event=cutover.voter_degraded" "$WORK/deg.log" || fail "no degraded alarm: $(head -5 "$WORK/deg.log")"
! grep -qE "vote submitted|delivered to coordinator" "$WORK/deg.log" || fail "the degraded voter signed or voted"
[[ "$(wc -l <"$WORK/deg-hits" 2>/dev/null || echo 0)" -ge 1 ]] || fail "the stub never saw a pause call"
kill "$DEG_PID" 2>/dev/null || true; wait "$DEG_PID" 2>/dev/null || true
# An unreadable key file is the other way a config stops loading.
KEYFAIL_CFG="$WORK/voter-keyfail.json"
python3 - "$FLOW_BASE" "$KEYFAIL_CFG" <<'PYEOF'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg["vote_key_file"] = "/nonexistent/vote.key"
json.dump(cfg, open(sys.argv[2], "w"))
PYEOF
cp "$DEG_CFG.finalized" "$KEYFAIL_CFG.finalized"
"$VOTER_BIN" --config "$KEYFAIL_CFG" >"$WORK/keyfail.log" 2>&1 &
KEYFAIL_PID=$!
wait_for_log "$WORK/keyfail.log" "from the recorded state" "$KEYFAIL_PID" 40 || fail "an unreadable key file ended pause enforcement: $(tail -5 "$WORK/keyfail.log")"
kill "$KEYFAIL_PID" 2>/dev/null || true; wait "$KEYFAIL_PID" 2>/dev/null || true
# The operator saying stop is honoured even with a record.
DISABLED_CFG="$WORK/voter-disabled.json"
python3 - "$FLOW_BASE" "$DISABLED_CFG" <<'PYEOF'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg["enabled"] = False
json.dump(cfg, open(sys.argv[2], "w"))
PYEOF
cp "$DEG_CFG.finalized" "$DISABLED_CFG.finalized"
# The voter is expected to exit non-zero here; capture it without tripping errexit.
DISABLED_STATUS=0
"$VOTER_BIN" --config "$DISABLED_CFG" >"$WORK/disabled.log" 2>&1 || DISABLED_STATUS=$?
[[ "$DISABLED_STATUS" == 1 ]] || fail "enabled=false should stop the voter (exit 1), got $DISABLED_STATUS: $(tail -3 "$WORK/disabled.log")"
! grep -q "from the recorded state" "$WORK/disabled.log" || fail "a disabled voter still enforced the pause"
kill "$STUB_PID" 2>/dev/null || true; wait "$STUB_PID" 2>/dev/null || true
pass "a voter whose config stops loading keeps the pause and signs nothing; enabled=false still stops it"

echo "cutover-voter-test: unverified pause never goes quiet..."
start_stub false "$WORK/pause-bad-hits" "$WORK/stub-bad.port"
STUB_BAD_PORT="$(cat "$WORK/stub-bad.port")"
# The pause path sits behind a delivered confirmation, so this run needs a
# good coordinator too: the point is the pause failing, not the delivery.
python3 "$WORK/coordinator.py" "$API" good "$WORK/confirmations-pausebad.jsonl" "$H" "$WORK/coord-pausebad.port" "$PLATFORM" "$NEW_CHAIN" >>"$WORK/coordinator-pausebad.log" 2>&1 &
COORD_PID=$!
for _ in $(seq 1 30); do
    [[ -s "$WORK/coord-pausebad.port" ]] && break
    kill -0 "$COORD_PID" 2>/dev/null || fail "pausebad coordinator died on startup"
    sleep 1
done
COORD_BADGOOD_PORT="$(cat "$WORK/coord-pausebad.port")"
PAUSEBAD_CFG="$(mk_config "$H" false "http://127.0.0.1:${COORD_BADGOOD_PORT}" "$PLATFORM" "http://127.0.0.1:${STUB_BAD_PORT}")"
"$VOTER_BIN" --config "$PAUSEBAD_CFG" --max-polls 8 >"$WORK/pausebad.log" 2>&1
kill "$STUB_PID" 2>/dev/null || true
wait "$STUB_PID" 2>/dev/null || true
kill "$COORD_PID" 2>/dev/null || true
wait "$COORD_PID" 2>/dev/null || true
grep -q "producer pause failed" "$WORK/pausebad.log" || fail "pause failure went unlogged: $(tail -5 "$WORK/pausebad.log")"
pass "unverified pause fails loud, never silent"

echo "cutover-voter-test: the pause lands before a hung coordinator is even tried..."
start_stub true "$WORK/pause-hang-hits" "$WORK/stub-hang.port"
HANG_STUB_PID="$STUB_PID"
HANG_STUB_PORT="$(cat "$WORK/stub-hang.port")"
# A coordinator that accepts connections and never answers: every call costs
# the voter's full HTTP timeout. The pause must not queue behind it.
python3 -I - "$WORK/hang.port" <<'PYEOF' &
import socket, sys
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(16)
open(sys.argv[1], "w").write(str(srv.getsockname()[1]))
held = []
while True:
    conn, _ = srv.accept()
    held.append(conn)
PYEOF
HANG_SRV_PID=$!
for _ in $(seq 1 30); do
    [[ -s "$WORK/hang.port" ]] && break
    sleep 1
done
HANG_PORT="$(cat "$WORK/hang.port")"
HANG_CFG="$(mk_config "$H" false "http://127.0.0.1:${HANG_PORT}" "$PLATFORM" "http://127.0.0.1:${HANG_STUB_PORT}")"
"$VOTER_BIN" --config "$HANG_CFG" >"$WORK/hang.log" 2>&1 &
HANG_VOTER_PID=$!
HANG_PAUSED=""
for _ in $(seq 1 60); do
    grep -q "local producer paused at P=" "$WORK/hang.log" 2>/dev/null && { HANG_PAUSED=1; break; }
    kill -0 "$HANG_VOTER_PID" 2>/dev/null || break
    sleep 1
done
# Give the confirmation attempt time to time out so its line exists to compare.
for _ in $(seq 1 40); do
    grep -q "confirmation failed" "$WORK/hang.log" 2>/dev/null && break
    sleep 1
done
kill "$HANG_VOTER_PID" "$HANG_SRV_PID" "$HANG_STUB_PID" 2>/dev/null || true
wait "$HANG_VOTER_PID" "$HANG_SRV_PID" "$HANG_STUB_PID" 2>/dev/null || true
[[ -n "$HANG_PAUSED" ]] || fail "producer never paused behind a hung coordinator: $(tail -5 "$WORK/hang.log")"
PAUSE_LINE="$(grep -n "local producer paused at P=" "$WORK/hang.log" | head -1 | cut -d: -f1)"
FAIL_LINE="$(grep -n "confirmation failed" "$WORK/hang.log" | head -1 | cut -d: -f1 || true)"
[[ -z "$FAIL_LINE" || "$PAUSE_LINE" -lt "$FAIL_LINE" ]] \
    || fail "pause (line $PAUSE_LINE) came after the hung confirmation (line $FAIL_LINE)"
pass "pause fires before the coordinator, which never answered"

echo "cutover-voter-test: PASS"
