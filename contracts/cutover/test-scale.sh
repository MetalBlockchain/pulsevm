#!/usr/bin/env bash
# Scale test for the cutover ceremony contract on a throwaway single-node
# Leap chain: 21 rostered producers with distinct mainnet-scale weights.
# Proves the freeze, declaration digest, and strict 2/3+1 tally hold at a
# realistic roster size, and that the frozen set governs after live-table
# drift (vote bumps plus a key rotation between freeze and voting).
#
# What this does NOT prove: a staged Leap schedule change (pending /
# proposed) cannot exist on this fixture chain — there is no system
# contract to call set_proposed_producers. Rotation refusal stays
# unit-tested (voter schedule-blocked, exporter init refusal).
#
# Nothing here touches mainnet. The seeder contract is fixture-only.
set -u
cd "$(dirname "$0")/../.."
REPO_ROOT="$PWD"
SCRIPT_DIR="$REPO_ROOT/contracts/cutover"
IMG="${XPR_NODEOS_IMAGE:-pulsevm-xpr-handover:local}"
PLATFORM="${XPR_PLATFORM:-linux/arm64}"
PORT="${CUTOVER_SCALE_PORT:-18995}"
API="http://127.0.0.1:${PORT}"
WORK="$(mktemp -d /tmp/cutover-scale-test.XXXXXX)"
NODE="cutover-scale-test-node"
PROBE="$REPO_ROOT/target/debug/examples/make_probe_tx"

fail() { echo "cutover-scale-test: FAIL: $*" >&2; exit 1; }
pass() { echo "cutover-scale-test: ok: $*"; }
cleanup() {
    docker rm -f "$NODE" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "cutover-scale-test: building the probe tool..."
(cd "$REPO_ROOT" && cargo build --locked -p pulsevm_core --example make_probe_tx) \
    || fail "probe tool build failed"
[[ -x "$PROBE" ]] || fail "probe tool missing"

DEV_WIF="$(grep -o 'KEY:[A-Za-z0-9]*' "$REPO_ROOT/tools/xpr-chainbase-export/localnet/producer-config.ini" | head -1 | cut -d: -f2)"
[[ -n "$DEV_WIF" ]] || fail "fixture dev key not found"

echo "cutover-scale-test: starting throwaway Leap node..."
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
    echo "cutover-scale-test: rpc $1 failed (HTTP $code)" >&2
    return 1
}
tapos() {
    rpc /v1/chain/get_info '{}' | python3 -c \
        'import json,sys; i=json.load(sys.stdin); print(i["head_block_num"], i["chain_id"])'
}
table_rows() {
    rpc /v1/chain/get_table_rows \
        "{\"code\":\"$1\",\"scope\":\"$2\",\"table\":\"$3\",\"limit\":200,\"json\":true}" \
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
    read -r ref_num ref_prefix <<<"$(rpc /v1/chain/get_block "{\"block_num_or_id\":$head}" | python3 -c \
        'import json,sys; b=json.load(sys.stdin); print(b["block_num"] & 0xffff, b["ref_block_prefix"])')"
    exp=$(( $(date +%s) + 1800 ))
    "$PROBE" "$mode" "$chain" "$wif" "$ref_num" "$ref_prefix" "$exp" "$@"
}
mk_push() { push_issue "$(mk_tx "$@")"; }

read -r HEAD_NUM CHAIN_ID <<<"$(tapos)"
echo "cutover-scale-test: chain $CHAIN_ID at head $HEAD_NUM"

echo "cutover-scale-test: deploying ceremony and seeder contracts..."
mk_push newaccount "$CHAIN_ID" "$DEV_WIF" cutover >/dev/null
mk_push setcode "$CHAIN_ID" "$DEV_WIF" cutover "$SCRIPT_DIR/cutover.wasm" >/dev/null
mk_push setabi "$CHAIN_ID" "$DEV_WIF" cutover "$SCRIPT_DIR/cutover.abi" >/dev/null
mk_push setcode "$CHAIN_ID" "$DEV_WIF" eosio "$SCRIPT_DIR/seed.wasm" >/dev/null
mk_push setabi "$CHAIN_ID" "$DEV_WIF" eosio "$SCRIPT_DIR/seed.abi" >/dev/null

echo "cutover-scale-test: seeding 21 producers with distinct mainnet-scale weights..."
declare -a BP_WIF BP_PUB BP_NAME BP_W
for i in $(seq 0 20); do
    letter="$(printf '%b' "$(printf '\\x%x' $((97 + i)))")"
    BP_NAME[$i]="p${letter}test"
    # Descending mainnet-scale weights, all distinct, all under the seed
    # contract's 1e30 ceiling.
    BP_W[$i]="$(python3 -c "print(21000000000000000000000 - $i * 1000000000000000000000 + $i)")"
    read -r wif pub32 <<<"$("$PROBE" newkey)"
    BP_WIF[$i]="$wif"
    BP_PUB[$i]="$("$PROBE" pubkey "$wif")"
done
for i in $(seq 0 20); do
    VOTES_HEX="$(python3 -c "import struct; print(struct.pack('<d', float(${BP_W[$i]})).hex())")"
    mk_push cseed "$CHAIN_ID" "$DEV_WIF" eosio eosio "${BP_NAME[$i]}" "$VOTES_HEX" "${BP_PUB[$i]}" 1 >/dev/null
done
NROWS="$(table_rows eosio eosio producers | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
[[ "$NROWS" == "21" ]] || fail "expected 21 seeded rows, got $NROWS"
pass "21 producers seeded"

H1=$(( $(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])') + 80 ))
echo "cutover-scale-test: freezing at H1=$H1..."
mk_push raw "$CHAIN_ID" "$DEV_WIF" cutover init cutover \
    "$(python3 -c "import struct; print((struct.pack('<I', $H1) + bytes.fromhex('$CHAIN_ID')).hex())")" >/dev/null
table_rows cutover cutover members \
    | python3 -c 'import json,sys; print(json.dumps([{"producer":r["producer"],"key":r["key"],"weight":r["weight"]} for r in json.load(sys.stdin)]))' \
    >"$WORK/members.json"
NMEMBERS="$(python3 -c 'import json; print(len(json.load(open("'$WORK'/members.json"))))')"
[[ "$NMEMBERS" == "21" ]] || fail "frozen roster has $NMEMBERS members, expected 21"
pass "frozen roster holds all 21 producers"
FROZEN_DIGEST="$(table_rows cutover cutover ceremony | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["declaration_digest"])')"
FROZEN_TOTAL="$(table_rows cutover cutover ceremony | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["total_weight"])')"

echo "cutover-scale-test: declaration digest recomputed independently over 21 members..."
python3 - "$WORK/members.json" "$CHAIN_ID" "$H1" "$FROZEN_DIGEST" "$FROZEN_TOTAL" <<'PYEOF'
import hashlib, json, struct, sys
DOMAIN = b"PULSEVM-XPR-HALT-DECLARATION-v1"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw
def eos_key_to_bytes(s):
    body = s[3:] if s.startswith("EOS") else s[7:]
    assert s.startswith("EOS") or s.startswith("PUB_K1_"), s
    raw = b58decode(body)
    assert len(raw) == 37, len(raw)
    import hashlib as hl
    assert raw[-4:] == hl.new("ripemd160", raw[:-4]).digest()[:4], "key checksum"
    return raw[:33]
members = sorted(json.load(open(sys.argv[1])), key=lambda m: m["producer"])
chain = bytes.fromhex(sys.argv[2])
h = int(sys.argv[3])
msg = bytearray(DOMAIN) + chain + struct.pack(">I", h) + struct.pack(">I", len(members))
for m in members:
    name = m["producer"].encode()
    msg += struct.pack(">I", len(name)) + name
    msg += eos_key_to_bytes(m["key"])
    msg += int(m["weight"]).to_bytes(16, "big")
digest = hashlib.sha256(bytes(msg)).hexdigest()
assert digest == sys.argv[4], f"digest mismatch:\n contract {sys.argv[4]}\n python   {digest}"
expected_total = sum(int(m["weight"]) for m in members)
assert expected_total == int(sys.argv[5]), f"tally mismatch: contract {sys.argv[5]} python {expected_total}"
print(f"digest + tally match over {len(members)} members")
PYEOF
pass "21-member digest and tally match bit-for-bit"

echo "cutover-scale-test: drifting the live table after the freeze..."
# Vote bumps on three members plus a full key rotation on a fourth: the
# frozen set must govern anyway.
for i in 0 1 2; do
    BUMP_HEX="$(python3 -c "import struct; print(struct.pack('<d', float(${BP_W[$i]}) * 1.5).hex())")"
    mk_push cseed "$CHAIN_ID" "$DEV_WIF" eosio eosio "${BP_NAME[$i]}" "$BUMP_HEX" "${BP_PUB[$i]}" 1 >/dev/null
done
read -r NEW_WIF NEW_WIF_PUB32 <<<"$("$PROBE" newkey)"
# NOTE: newkey prints the 32-byte x-only hex; the canonical 33-byte form
# (with prefix) comes from `pubkey`, and that is what member keys need.
NEW_PUB33="$("$PROBE" pubkey "$NEW_WIF")"
NEW_PUB="$NEW_PUB33"
SAME_W_HEX="$(python3 -c "import struct; print(struct.pack('<d', float(${BP_W[3]})).hex())")"
mk_push cseed "$CHAIN_ID" "$DEV_WIF" eosio eosio "${BP_NAME[3]}" "$SAME_W_HEX" "$NEW_PUB" 1 >/dev/null
pass "live table drifted under the frozen set"
# The frozen total must be untouched by live drift.
FROZEN_TOTAL2="$(table_rows cutover cutover ceremony | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["total_weight"])')"
[[ "$FROZEN_TOTAL2" == "$FROZEN_TOTAL" ]] || fail "frozen total moved with live drift"
pass "frozen tally pinned despite drift"

echo "cutover-scale-test: rotated key must fail (not in the frozen set)..."
python3 - "$WORK/members.json" "$WORK/rotated-members.json" "${BP_NAME[3]}" "$NEW_PUB33" <<'PYEOF'
import hashlib, json, sys
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58encode(raw):
    n = int.from_bytes(raw, "big")
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = B58[r] + s
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + s
# Canonical PUB_K1_ rendering of the raw compressed key, the same form the
# node renders on-chain rows in: base58 of key plus the 4-byte ripemd160
# checksum over (key || b"K1"). The K1 suffix is what distinguishes the
# modern form from legacy EOS keys (verified 64/64 against the C++ oracle
# KATs in crates/pulsevm_crypto/tests/k1_kat.txt). The probe only parses
# member keys in this string form.
raw = bytes.fromhex(sys.argv[4])
key = "PUB_K1_" + b58encode(raw + hashlib.new("ripemd160", raw + b"K1").digest()[:4])
members = json.load(open(sys.argv[1]))
for m in members:
    if m["producer"] == sys.argv[3]:
        m["key"] = key
json.dump(members, open(sys.argv[2], "w"))
print("rotated key renders as", key[:20] + "...")
PYEOF
if out="$(mk_push cvote "$CHAIN_ID" "$DEV_WIF" cutover cutover "${BP_NAME[3]}" "$NEW_WIF" "$H1" "$CHAIN_ID" "$WORK/rotated-members.json" 2>&1)"; then
    fail "rotated key vote unexpectedly succeeded: $out"
fi
[[ "$out" == *"frozen"* ]] || fail "rotated key failed without the frozen-set reason: $out"
pass "rotated key refused"

echo "cutover-scale-test: voting the minimal quorum prefix to finalize..."
QUORUM_JSON="$(python3 - "$WORK/members.json" <<'PYEOF'
import json, sys
members = sorted(json.load(open(sys.argv[1])), key=lambda m: int(m["weight"]), reverse=True)
total = sum(int(m["weight"]) for m in members)
signed, idxs = 0, []
for i, m in enumerate(members):
    signed += int(m["weight"])
    idxs.append(i)
    if signed * 3 > total * 2:
        break
print(json.dumps({"total": total, "indices": idxs}))
PYEOF
)"
echo "cutover-scale-test: quorum needs producers: $QUORUM_JSON"
LAST_IDX="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["indices"][-1])' <<<"$QUORUM_JSON")"
python3 - "$WORK/members.json" "$QUORUM_JSON" >"$WORK/quorum-names.txt" <<'PYEOF2'
import json, sys
members = {m["producer"]: m for m in json.load(open(sys.argv[1]))}
ranked = sorted(members, key=lambda n: int(members[n]["weight"]), reverse=True)
indices = json.loads(sys.argv[2])["indices"][:-1]
print("\n".join(ranked[i] for i in indices))
PYEOF2
while read -r NAME; do
    for j in $(seq 0 20); do
        if [[ "${BP_NAME[$j]}" == "$NAME" ]]; then IDX="$j"; break; fi
    done
    mk_push cvote "$CHAIN_ID" "$DEV_WIF" cutover cutover "$NAME" "${BP_WIF[$IDX]}" "$H1" "$CHAIN_ID" "$WORK/members.json" >/dev/null
done <"$WORK/quorum-names.txt"
VOTED="$(table_rows cutover cutover ceremony | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["finalized"])')"
[[ "$VOTED" == "0" ]] || fail "quorum-minus-one finalized early"
LAST_NAME="$(python3 - "$WORK/members.json" "$LAST_IDX" <<'PYEOF2'
import json, sys
members = sorted(json.load(open(sys.argv[1])), key=lambda m: int(m["weight"]), reverse=True)
print(members[int(sys.argv[2])]["producer"])
PYEOF2
)"
for j in $(seq 0 20); do
    if [[ "${BP_NAME[$j]}" == "$LAST_NAME" ]]; then LAST_J="$j"; break; fi
done
mk_push cvote "$CHAIN_ID" "$DEV_WIF" cutover cutover "$LAST_NAME" "${BP_WIF[$LAST_J]}" "$H1" "$CHAIN_ID" "$WORK/members.json" >/dev/null
VOTED="$(table_rows cutover cutover ceremony | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["finalized"])')"
[[ "$VOTED" == "1" ]] || fail "quorum prefix did not finalize"
pass "21-member quorum finalized at strict 2/3+1"

echo "cutover-scale-test: PASS"
