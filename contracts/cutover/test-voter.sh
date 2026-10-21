#!/usr/bin/env bash
# Live test for the cutover auto-voter on a throwaway single-node Leap chain:
# deploys the ceremony contract, freezes a one-member schedule, then proves
# the voter (1) refuses a foreign freeze in dry-run without signing anything,
# (2) signs and submits a real vote unattended, and (3) delivers the
# confirmation to a coordinator that serves live chain data -- while refusing
# a coordinator that lies about the terminal block id.
set -u
cd "$(dirname "$0")/../.."
REPO_ROOT="$PWD"
SCRIPT_DIR="$REPO_ROOT/contracts/cutover"
IMG="${XPR_NODEOS_IMAGE:-pulsevm-xpr-handover:local}"
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
(cd "$REPO_ROOT" && cargo build --locked -p pulsevm_core --example xpr_cutover_voter --example make_probe_tx) \
    || fail "tool build failed"
[[ -x "$VOTER_BIN" ]] || fail "voter binary missing"
[[ -x "$PROBE_BIN" ]] || fail "probe binary missing"

DEV_WIF="$(grep -o 'KEY:[A-Za-z0-9]*' "$REPO_ROOT/tools/xpr-chainbase-export/localnet/producer-config.ini" | head -1 | cut -d: -f2)"
[[ -n "$DEV_WIF" ]] || fail "fixture dev key not found"

echo "cutover-voter-test: starting throwaway Leap node..."
docker rm -f "$NODE" >/dev/null 2>&1 || true
docker run --detach --platform "$PLATFORM" --name "$NODE" \
    -v "$REPO_ROOT/tools/xpr-chainbase-export/localnet/genesis.json:/config-env/genesis.json:ro" \
    -v "$REPO_ROOT/tools/xpr-chainbase-export/localnet/producer-config.ini:/config/config.ini:ro" \
    -p "127.0.0.1:${PORT}:8888" \
    "$IMG" \
    nodeos --data-dir=/data --config-dir=/config --genesis-json=/config-env/genesis.json \
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

echo "cutover-voter-test: deploying ceremony contract and seeding one producer..."
read -r BP_WIF BP_PUB32 <<<"$("$PROBE_BIN" newkey)"
# NOTE: newkey prints raw compressed hex; the canonical display form comes
# from the frozen on-chain row (see roster.json below), never hand-built.
mk_push newaccount "$CHAIN_ID" "$DEV_WIF" cutover >/dev/null
mk_push setcode "$CHAIN_ID" "$DEV_WIF" cutover "$SCRIPT_DIR/cutover.wasm" >/dev/null
mk_push setabi "$CHAIN_ID" "$DEV_WIF" cutover "$SCRIPT_DIR/cutover.abi" >/dev/null
mk_push setcode "$CHAIN_ID" "$DEV_WIF" eosio "$SCRIPT_DIR/seed.wasm" >/dev/null
mk_push setabi "$CHAIN_ID" "$DEV_WIF" eosio "$SCRIPT_DIR/seed.abi" >/dev/null
VOTES_HEX="$(python3 -c 'import struct; print(struct.pack("<d", 1.0).hex())')"
PUB33="$("$PROBE_BIN" pubkey "$BP_WIF")"
mk_push cseed "$CHAIN_ID" "$DEV_WIF" eosio eosio bpvoter "$VOTES_HEX" "$PUB33" 1 >/dev/null
pass "contract deployed, one producer seeded"

H=$(( $(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])') + 60 ))
echo "cutover-voter-test: init H=$H..."
mk_push raw "$CHAIN_ID" "$DEV_WIF" cutover init cutover \
    "$(python3 -c "import struct; print((struct.pack('<I', $H) + bytes.fromhex('$CHAIN_ID')).hex())")" >/dev/null
FROZEN_DIGEST="$(table_rows cutover cutover ceremony | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["declaration_digest"])')"
[[ -n "$FROZEN_DIGEST" ]] || fail "no frozen ceremony"
pass "ceremony frozen at H=$H"

# Voter key files must be owner-only or the voter refuses to start.
printf '%s' "$BP_WIF" >"$WORK/vote.key"; chmod 600 "$WORK/vote.key"
printf '%s' "$DEV_WIF" >"$WORK/payer.key"; chmod 600 "$WORK/payer.key"
# The roster mirrors the frozen on-chain member row byte-for-byte (whatever
# string form the node renders): the recomputed digest must equal the
# frozen one, or the voter refuses to sign.
table_rows cutover cutover members \
    | python3 -c 'import json,sys; print(json.dumps([{"producer":r["producer"],"key":r["key"],"weight":r["weight"]} for r in json.load(sys.stdin)]))' \
    >"$WORK/roster.json"
mk_config() { # $1=height $2=dry $3=coord-url-or-empty -> path
    local out="$WORK/voter-$RANDOM.json"
    local coord="null"
    [[ -n "${3:-}" ]] && coord="\"$3\""
    cat >"$out" <<EOF
{"nodeos_url":"http://127.0.0.1:${PORT}","contract":"cutover","producer":"bpvoter",
 "source_chain_id":"$CHAIN_ID","height":$1,"roster_file":"$WORK/roster.json",
 "vote_key_file":"$WORK/vote.key","payer_account":"eosio","payer_key_file":"$WORK/payer.key",
 "poll_secs":1,"dry_run":$2,"enabled":true,
 "confirmation":{"coordinator_url":$coord,"out_file":"$WORK/confirmation.json",
  "migration_genesis":null,"checkpoint_sha256":null}}
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

# Coordinator serving live chain data: block id is read from the node itself,
# so it always matches; the voter must still verify every field.
cat >"$WORK/coordinator.py" <<'PYEOF'
import json, sys, urllib.request
node, mode, out = sys.argv[1], sys.argv[2], sys.argv[3]
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
        body = {"halt_height": h, "halt_block_id": blk["id"] if mode == "good" else "00" * 32,
                "checkpoint_sha256": "ab" * 32, "new_chain_id": "cd" * 32,
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
python3 "$WORK/coordinator.py" "$API" good "$WORK/confirmations.jsonl" "$H" "$WORK/coord.port" >>"$WORK/coordinator.log" 2>&1 &
COORD_PID=$!
for _ in $(seq 1 30); do
    [[ -s "$WORK/coord.port" ]] && break
    kill -0 "$COORD_PID" 2>/dev/null || fail "coordinator died on startup: $(cat "$WORK/coordinator.log")"
    sleep 1
done
COORD_PORT="$(cat "$WORK/coord.port")"
LIVE_CFG="$(mk_config "$H" false "http://127.0.0.1:${COORD_PORT}")"
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
CONF_PRODUCER="$(python3 -c 'import json; print(json.load(open("'"$WORK/confirmations.jsonl"'"))["producer"])')"
[[ "$CONF_PRODUCER" == "bpvoter" ]] || fail "coordinator got no well-formed confirmation"
pass "vote landed and confirmation delivered unattended"

echo "cutover-voter-test: lying coordinator is refused..."
python3 "$WORK/coordinator.py" "$API" bad "$WORK/confirmations-bad.jsonl" "$H" "$WORK/coord-bad.port" >>"$WORK/coordinator-bad.log" 2>&1 &
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
"$VOTER_BIN" --config "$BAD_CFG" --max-polls 4 >"$WORK/bad.log" 2>&1 &
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

echo "cutover-voter-test: PASS"
