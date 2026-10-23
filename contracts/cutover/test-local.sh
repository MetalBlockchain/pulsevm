#!/usr/bin/env bash
# Fixture test for the cutover ceremony contract on a throwaway single-node
# Leap chain. Seeds a synthetic schedule (mainnet-scale vote weights),
# freezes it via init, and exercises every vote path: outsider rejection,
# wrong-height digest, double vote, boundary quorum (not-finalized then
# finalized at strict 2/3+1), post-finalize and post-vote re-init rejection,
# plus an independent Python reimplementation of the declaration digest and
# the u128 tally that must match the contract bit-for-bit. The freeze
# window (init_time stamp, re-init re-stamp) is asserted as plumbing; the
# 7-day expiry itself is not exercised here — no test chain can wait it
# out, and time-travel would invalidate the fixture — so expiry is covered
# by the voter predicate unit tests (same constant, same comparison) plus
# the boundary that a live freeze always carries a sane init_time.
#
# Nothing here touches mainnet. The seeder contract is fixture-only.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMG="${XPR_NODEOS_IMAGE:-pulsevm-xpr-handover:local}"
PLATFORM="${XPR_PLATFORM:-linux/arm64}"
PORT="${CUTOVER_TEST_PORT:-18893}"
API="http://127.0.0.1:${PORT}"
WORK="$(mktemp -d /tmp/cutover-test.XXXXXX)"
NODE="cutover-test-node"

fail() { echo "cutover-fixture: FAIL: $*" >&2; exit 1; }
pass() { echo "cutover-fixture: ok: $*"; }
CHECKS=0
check() { CHECKS=$((CHECKS + 1)); pass "$1"; }

cleanup() {
    docker rm -f "$NODE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "cutover-fixture: building the probe tool..."
(cd "$REPO_ROOT" && cargo build --offline -p pulsevm_core --example make_probe_tx) \
    || fail "probe tool build failed"
PROBE="$REPO_ROOT/target/debug/examples/make_probe_tx"
[[ -x "$PROBE" ]] || fail "probe tool missing"
(cd "$REPO_ROOT" && cargo build --offline -p pulsevm_core --example xpr_scan_contract_votes) \
    || fail "scanner build failed"
SCANNER="$REPO_ROOT/target/debug/examples/xpr_scan_contract_votes"
[[ -x "$SCANNER" ]] || fail "scanner missing"

DEV_WIF="$(grep -o 'KEY:[A-Za-z0-9]*' "$REPO_ROOT/tools/xpr-chainbase-export/localnet/producer-config.ini" | head -1 | cut -d: -f2)"
[[ -n "$DEV_WIF" ]] || fail "fixture dev key not found"

echo "cutover-fixture: starting throwaway Leap node..."
# A killed run can leave the throwaway node behind (plain `docker run`,
# so nothing else reaps it).
docker rm -f "$NODE" >/dev/null 2>&1 || true
docker run --detach --platform "$PLATFORM" --name "$NODE" \
    -v "$REPO_ROOT/tools/xpr-chainbase-export/localnet/genesis.json:/config-env/genesis.json:ro" \
    -v "$REPO_ROOT/tools/xpr-chainbase-export/localnet/producer-config.ini:/config/config.ini:ro" \
    -p "127.0.0.1:${PORT}:8888" \
    "$IMG" \
    nodeos --data-dir=/data --config-dir=/config --genesis-json=/config-env/genesis.json \
    >/dev/null || fail "node start failed"
# Leap validates the HTTP Host header against its listening address.
for _ in $(seq 1 90); do
    # The || true keeps set -e from killing the wait on a not-ready node.
    HEAD_NOW="$(curl --fail --silent --max-time 5 -X POST "$API/v1/chain/get_info" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d '{}' 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])' 2>/dev/null || true)"
    # A node answering get_info at head 3 still rejects the first pushes;
    # wait until it is actually producing.
    if [[ -n "${HEAD_NOW:-}" && "$HEAD_NOW" -ge 10 ]]; then
        break
    fi
    sleep 1
done
[[ -n "${HEAD_NOW:-}" && "$HEAD_NOW" -ge 10 ]] || fail "node never reached head 10"

rpc() { # path json -> stdout; fails loudly with the response body
    local out code
    out="$(curl --silent --show-error --max-time 20 -X POST "$API$1" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d "$2" -w '\nHTTP_CODE:%{http_code}\n' 2>&1)"
    code="$(printf '%s' "$out" | grep -o 'HTTP_CODE:[0-9]*' | cut -d: -f2)"
    [[ "$code" == "200" || "$code" == "201" || "$code" == "202" ]] \
        && { printf '%s' "$out" | sed '/^HTTP_CODE:/d'; return 0; }
    echo "cutover-fixture: rpc $1 failed (HTTP $code): $(printf '%s' "$out" | head -c 600)" >&2
    return 1
}
# "ref_num ref_prefix chain_id head" for tapos.
tapos() {
    rpc /v1/chain/get_info '{}' | python3 -c \
        'import json,sys; i=json.load(sys.stdin); print(i["head_block_num"], i["chain_id"])'
}
ref_prefix() { # $1=head -> "ref_num ref_prefix"
    rpc /v1/chain/get_block "{\"block_num_or_id\":$1}" | python3 -c \
        'import json,sys; b=json.load(sys.stdin); print(b["block_num"] & 0xffff, b["ref_block_prefix"])'
}
push_tx() { # $1 = issueTx body -> prints txid or fails (loudly)
    local body send_out txid
    body="$(printf '%s' "$1" | python3 -c 'import json,sys; p=json.load(sys.stdin)["params"]; print(json.dumps({"signatures":p["signatures"],"compression":"none","packed_context_free_data":p["packed_context_free_data"],"packed_trx":p["packed_trx"]}))')" \
        || fail "refusing to submit an unparseable issueTx body"
    # NOTE: rpc() takes the JSON as an argument, so the piped body needs a
    # direct curl with -d @- here, not rpc ... /dev/stdin (which would send
    # the literal path as the transaction).
    send_out="$(printf '%s' "$body" | curl --silent --show-error --max-time 20 \
        -X POST "$API/v1/chain/send_transaction" \
        -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d @- -w '\nHTTP_CODE:%{http_code}\n' 2>&1)"
    local http_code
    http_code="$(printf '%s' "$send_out" | grep -o 'HTTP_CODE:[0-9]*' | cut -d: -f2)"
    [[ "$http_code" == "200" || "$http_code" == "201" || "$http_code" == "202" ]] \
        || fail "send_transaction rejected the transaction (HTTP $http_code): $(printf '%s' "$send_out" | head -c 600)"
    send_out="$(printf '%s' "$send_out" | sed '/^HTTP_CODE:/d')"
    txid="$(printf '%s' "$send_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["transaction_id"])' 2>&1)" \
        || fail "send_transaction returned no txid: $send_out"
    printf '%s\n' "$txid"
}
expect_fail() { # $1 desc, $2 expected-substring, rest = push command...
    local desc="$1" want="$2"; shift 2
    local out
    if out="$("$@" 2>&1)"; then
        fail "$desc unexpectedly succeeded: $out"
    fi
    [[ "$out" == *"$want"* ]] || fail "$desc failed without [$want]: $out"
    check "$desc rejected"
}
table_rows() { # $1=code $2=scope $3=table -> rows json
    rpc /v1/chain/get_table_rows \
        "{\"code\":\"$1\",\"scope\":\"$2\",\"table\":\"$3\",\"limit\":100,\"json\":true}" \
        | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["rows"]))'
}

read -r HEAD_NUM CHAIN_ID <<<"$(tapos)"
echo "cutover-fixture: chain $CHAIN_ID at head $HEAD_NUM"
[[ "$CHAIN_ID" != "0000000000000000000000000000000000000000000000000000000000000000" ]] \
    || fail "chain id unreadable"

# Four BPs with mainnet-scale weights, plus one inactive row the freeze
# must skip. Weights chosen so bp1 alone (44%) cannot finalize, bp1+bp2
# (70.7%) can: the strict boundary, with real magnitudes.
BP_W1=5.251494364735212e21
BP_W2=3.1e21
BP_W3=3.0e21
BP_W4=1.5e20
BP_INACTIVE_W=9.0e21
declare -a BP_WIF BP_PUB BP_NAME
for i in 0 1 2 3 4; do
    read -r wif pub32 <<<"$("$PROBE" newkey)"
    BP_WIF[$i]="$wif"
    BP_PUB[$i]="$("$PROBE" pubkey "$wif")"
    BP_NAME[$i]="bp$(printf '%s' abcde | cut -c$((i + 1)))test"
done
echo "cutover-fixture: BPs ${BP_NAME[*]}"

# Every probe mode takes tapos as <chain-id> <wif> <ref-num> <ref-prefix>
# <exp> followed by mode args, so mk_tx splices fresh tapos after <wif>.
mk_tx() { # $mode $chain $wif [mode-args...] -> issueTx body
    local mode="$1" chain="$2" wif="$3"
    shift 3
    local head
    head="$(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])')"
    read -r ref_num ref_prefix <<<"$(ref_prefix "$head")"
    local exp=$(( $(date +%s) + 1800 ))
    "$PROBE" "$mode" "$chain" "$wif" "$ref_num" "$ref_prefix" "$exp" "$@"
}
mk_push() { push_tx "$(mk_tx "$@")"; }

echo "cutover-fixture: creating contract account..."
mk_push newaccount "$CHAIN_ID" "$DEV_WIF" cutover >/dev/null
check "account created"

echo "cutover-fixture: deploying contracts..."
mk_push setcode "$CHAIN_ID" "$DEV_WIF" cutover "$SCRIPT_DIR/cutover.wasm" >/dev/null
mk_push setabi "$CHAIN_ID" "$DEV_WIF" cutover "$SCRIPT_DIR/cutover.abi" >/dev/null
# The seeder must run as code `eosio`: Leap forbids creating objects in
# another contract's table, so only code=eosio can plant the fixture
# schedule rows. Fixture-only; the throwaway chain is discarded after.
mk_push setcode "$CHAIN_ID" "$DEV_WIF" eosio "$SCRIPT_DIR/seed.wasm" >/dev/null
mk_push setabi "$CHAIN_ID" "$DEV_WIF" eosio "$SCRIPT_DIR/seed.abi" >/dev/null
check "contracts deployed"

f64hex() { python3 -c 'import struct,sys; print(struct.pack("<d", float(sys.argv[1])).hex())' "$1"; }
echo "cutover-fixture: seeding the synthetic schedule..."
mk_push cseed "$CHAIN_ID" "$DEV_WIF" eosio eosio "${BP_NAME[0]}" "$(f64hex "$BP_W1")" "${BP_PUB[0]}" 1 >/dev/null
mk_push cseed "$CHAIN_ID" "$DEV_WIF" eosio eosio "${BP_NAME[1]}" "$(f64hex "$BP_W2")" "${BP_PUB[1]}" 1 >/dev/null
mk_push cseed "$CHAIN_ID" "$DEV_WIF" eosio eosio "${BP_NAME[2]}" "$(f64hex "$BP_W3")" "${BP_PUB[2]}" 1 >/dev/null
mk_push cseed "$CHAIN_ID" "$DEV_WIF" eosio eosio "${BP_NAME[3]}" "$(f64hex "$BP_W4")" "${BP_PUB[3]}" 1 >/dev/null
mk_push cseed "$CHAIN_ID" "$DEV_WIF" eosio eosio "${BP_NAME[4]}" "$(f64hex "$BP_INACTIVE_W")" "${BP_PUB[4]}" 0 >/dev/null
check "5 rows seeded (4 active + 1 inactive)"

H1=$(( $(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])') + 20 ))
echo "cutover-fixture: init H=$H1..."
mk_push raw "$CHAIN_ID" "$DEV_WIF" cutover init cutover \
    "$(python3 -c "import struct; print((struct.pack('<I', $H1) + bytes.fromhex('$CHAIN_ID')).hex())")" >/dev/null
read -r FROZEN_H VOTED TOTAL FINALIZED DIGEST INIT_US <<<"$(
    table_rows cutover cutover ceremony | python3 -c '
import json,sys
c = json.load(sys.stdin)[0]
print(c["h"], c["voted_weight"], c["total_weight"], int(c["finalized"]), c["declaration_digest"], c["init_time"])' )"
# Frozen roster for the tool-built votes: weights as decimal strings keep
# mainnet magnitudes exact through JSON (no float round-trip).
table_rows cutover cutover members | python3 -c "
import json,sys
rows = json.load(sys.stdin)
members = [{'producer': r['producer'], 'key': r['key'], 'weight': str(int(r['weight']))} for r in rows]
json.dump(members, open('$WORK/members.json', 'w'))
print(len(rows))"
COUNT="$(python3 -c "import json; print(len(json.load(open('$WORK/members.json'))))")"
echo "cutover-fixture: frozen $COUNT members"
[[ "$FROZEN_H" == "$H1" ]] || fail "init froze wrong H"
[[ "$FINALIZED" == "0" ]] || fail "fresh ceremony finalized"
[[ "$COUNT" == "4" ]] || fail "init must freeze exactly the 4 active producers"
[[ "$VOTED" == "0" ]] || fail "fresh ceremony has votes"
check "init froze 4 active members at H=$H1 (inactive skipped)"
# Freeze instant bounds the vote window: it must be chain time (the fixture
# produces in real time, so within an hour of wall clock either way).
NOW_US="$(python3 -c 'import time; print(time.time_ns() // 1000)')"
[[ "$INIT_US" -gt 0 ]] || fail "init did not stamp init_time"
[[ "$INIT_US" -gt $((NOW_US - 3600 * 1000000)) ]] || fail "init_time is older than an hour: $INIT_US"
[[ "$INIT_US" -lt $((NOW_US + 3600 * 1000000)) ]] || fail "init_time is in the future: $INIT_US"
check "init stamped a sane freeze instant (window anchor present)"

# Re-init before any vote lands must move the freeze (liveness-only
# griefing vector); after the first vote the freeze locks. This runs here,
# on the still-voteless ceremony, so no second chain is needed.
echo "cutover-fixture: re-init before votes is allowed..."
H2=$((H1 + 7))
mk_push raw "$CHAIN_ID" "$DEV_WIF" cutover init cutover \
    "$(python3 -c "import struct; print((struct.pack('<I', $H2) + bytes.fromhex('$CHAIN_ID')).hex())")" >/dev/null
read -r FROZEN_H VOTED TOTAL FINALIZED DIGEST INIT_US2 <<<"$(
    table_rows cutover cutover ceremony | python3 -c '
import json,sys
c = json.load(sys.stdin)[0]
print(c["h"], c["voted_weight"], c["total_weight"], int(c["finalized"]), c["declaration_digest"], c["init_time"])' )"
[[ "$FROZEN_H" == "$H2" ]] || fail "re-init did not move the freeze"
[[ "$INIT_US2" -ge "$INIT_US" ]] || fail "re-init did not re-stamp init_time"
[[ "$FINALIZED" == "0" ]] || fail "voteless ceremony finalized"
[[ "$VOTED" == "0" ]] || fail "voteless ceremony has votes"
check "re-init moved the freeze to H=$H2"
H1=$H2

# Independent reimplementation of the declaration digest and the u128 tally:
# the contract must match this Python bit-for-bit (digest) and in value
# (tally), or the votes below fail. Weights are the script-known doubles,
# so no JSON float round-trip pollutes the comparison.
python3 - "$WORK/members.json" "$CHAIN_ID" "$H1" "$DIGEST" "$TOTAL" <<'PYEOF'
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
    # Leap renders public_key as PUB_K1_<base58>; legacy EOS<base58> is
    # accepted too. Payload is the 33-byte compressed key plus a 4-byte
    # ripemd160 checksum in both formats.
    if s.startswith("EOS"):
        body = s[3:]
    else:
        assert s.startswith("PUB_K1_"), s
        body = s[7:]
    raw = b58decode(body)
    assert len(raw) == 37, len(raw)
    import hashlib as hl
    assert raw[-4:] == hl.new("ripemd160", raw[:-4]).digest()[:4], "key checksum"
    assert raw[0] in (2, 3), "expected compressed K1 key"
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
print(f"digest match: {digest[:16]}...")

expected_total = sum(
    int(v)
    for v in (5.251494364735212e21, 3.1e21, 3.0e21, 1.5e20)
)
assert expected_total == int(sys.argv[5]), (
    f"tally mismatch: contract {sys.argv[5]} python {expected_total}"
)
print(f"tally match: total {expected_total}")
# python ints are exact: the quorum boundary below uses these, not floats.
w = [5.251494364735212e21, 3.1e21, 3.0e21, 1.5e20]
wi = [int(x) for x in w]
t = sum(wi)
assert wi[0] * 3 <= t * 2, "bp1 alone must not finalize"
assert (wi[0] + wi[1]) * 3 > t * 2, "bp1+bp2 must finalize"
print("quorum boundary confirmed in exact integers")
PYEOF
check "contract digest and tally match the independent implementation"

# Votes are relayed by the dev key on the cutover account (the voter
# signature inside the action, not the relay, is the authorization).
# Each push refreshes tapos internally.
do_vote() { # $1=bp-index [$2=height-override] [$3=members-override]
    local idx="$1" h="${2:-$H1}" members="${3:-$WORK/members.json}"
    push_tx "$(mk_tx cvote "$CHAIN_ID" "$DEV_WIF" cutover cutover \
        "${BP_NAME[$idx]}" "${BP_WIF[$idx]}" "$h" "$CHAIN_ID" "$members")"
}
# All vote helpers are defined before first use: expect_fail invokes them
# in a subshell at the call site, so definition order matters.
do_vote_outsider() {
    push_tx "$(mk_tx cvote "$CHAIN_ID" "$DEV_WIF" cutover cutover \
        mallorytest "$OUTSIDER_WIF" "$H1" "$CHAIN_ID" "$OUTSIDER_MEMBERS")"
}
do_vote_wrong_h() { do_vote 0 "$((H1 + 1))"; }
# A bit-identical retry would die as a node-level duplicate before reaching
# the contract; wait for a new head so the retry carries fresh tapos and the
# contract itself rejects the double vote.
do_vote_again() {
    local tip now
    tip="$(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])')"
    for _ in $(seq 1 20); do
        sleep 0.5
        now="$(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])')"
        [[ "$now" != "$tip" ]] && break
    done
    do_vote 0
}
do_vote_late() { do_vote 2; }
do_reinit_locked() {
    mk_push raw "$CHAIN_ID" "$DEV_WIF" cutover init cutover \
        "$(python3 -c "import struct; print((struct.pack('<I', $H3) + bytes.fromhex('$CHAIN_ID')).hex())")"
}

echo "cutover-fixture: outsider vote must fail..."
OUTSIDER_WIF="$("$PROBE" newkey | cut -d' ' -f1)"
OUTSIDER_MEMBERS="$WORK/outsider-members.json"
python3 - "$WORK/members.json" "$OUTSIDER_MEMBERS" <<'PYEOF'
import json, sys
members = json.load(open(sys.argv[1]))
members.append({"producer": "mallorytest", "key": members[0]["key"], "weight": "1"})
json.dump(members, open(sys.argv[2], "w"))
PYEOF
expect_fail "outsider vote" "not in the frozen validator set" \
    do_vote_outsider

echo "cutover-fixture: wrong-height vote must fail..."
expect_fail "wrong-height vote" "not from the frozen schedule key" \
    do_vote_wrong_h

echo "cutover-fixture: first valid vote (bp1, 44%: must NOT finalize)..."
TX1="$(do_vote 0)"
echo "cutover-fixture: vote tx $TX1"
read -r VOTED FINALIZED <<<"$(table_rows cutover cutover ceremony | python3 -c '
import json,sys
c = json.load(sys.stdin)[0]
print(c["voted_weight"], int(c["finalized"]))')"
[[ "$FINALIZED" == "0" ]] || fail "bp1 alone finalized at 44%"
check "bp1 vote counted, tally open"

echo "cutover-fixture: double vote must fail..."
expect_fail "double vote" "already voted" do_vote_again

echo "cutover-fixture: second vote (bp1+bp2, 70.7%: must finalize)..."
TX2="$(do_vote 1)"
echo "cutover-fixture: vote tx $TX2"
read -r VOTED FINALIZED <<<"$(table_rows cutover cutover ceremony | python3 -c '
import json,sys
c = json.load(sys.stdin)[0]
print(c["voted_weight"], int(c["finalized"]))')"
[[ "$FINALIZED" == "1" ]] || fail "bp1+bp2 did not finalize at 70.7%"
check "quorum reached: finalized at strict 2/3+1"

echo "cutover-fixture: post-finalize vote must fail..."
expect_fail "post-finalize vote" "already finalized" do_vote_late

echo "cutover-fixture: re-init after votes must fail (freeze locked)..."
H3=$((H1 + 30))
expect_fail "locked re-init" "freeze is locked" do_reinit_locked

# The exporter path, against live node data: scan the window for
# cutover::vote actions, capture the singleton, and check the fragment
# carries exactly the finalized on-chain tally as verifier evidence.
echo "cutover-fixture: scanning contract votes into verifier evidence..."
SCAN_TO="$(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])')"
SCAN_LOG="$WORK/scan.log"
"$SCANNER" --api "$API" --contract cutover --from 1 --to "$SCAN_TO" \
    --singleton-block "$SCAN_TO" --out "$WORK/fragment.json" \
    --declare-out "$WORK/declaration.json" \
    --host-header '0.0.0.0:8888' >"$SCAN_LOG" 2>&1 \
    || fail "vote scan failed: $(tail -3 "$SCAN_LOG")"
grep -q "schedule_version=0" "$SCAN_LOG" || fail "scanner must attest the unanimous schedule version"
python3 - "$WORK/fragment.json" "$WORK/declaration.json" "$DIGEST" "$TOTAL" "$VOTED" "$H1" "${BP_NAME[0]}" "${BP_NAME[1]}" <<'PYEOF'
import json, sys
frag = json.load(open(sys.argv[1]))
decl = json.load(open(sys.argv[2]))
digest, total, voted, h, bp1, bp2 = (sys.argv[3], int(sys.argv[4]),
    int(sys.argv[5]), int(sys.argv[6]), sys.argv[7], sys.argv[8])
assert frag["contract"] == "cutover", frag["contract"]
assert frag["declaration_digest"] == digest, "fragment digest must equal the frozen digest"
assert int(frag["total_weight"]) == total, "fragment total must equal the frozen roster"
assert int(frag["voted_weight"]) == voted, "fragment tally must equal the on-chain tally"
assert frag["finalized"] is True, "fragment must capture a completed tally"
assert frag["finalized_block"] < h, "finality must predate H"
assert len(frag["votes"]) == 2, f"want exactly the 2 counted votes, got {len(frag['votes'])}"
names = sorted(v["producer"] for v in frag["votes"])
assert names == sorted([bp1, bp2]), f"fragment voters {names} are not the quorum"
# The exporter-built declaration carries the frozen roster plus the scanned
# signatures; its digest is the ceremony digest by construction.
assert decl["last_height"] == h, "declaration must target H"
assert len(decl["signatures"]) == 2, "declaration must carry the 2 vote signatures"
assert decl["validator_set"] and len(decl["validator_set"]) == 4
for v in frag["votes"]:
    assert v["block"] < h, f"vote block {v['block']} must predate H={h}"
    # Leap renders the frozen K1 keys in legacy EOS form here; the Rust
    # verifier parses both PUB_K1_ and EOS forms.
    assert v["key"].startswith(("PUB_K1_", "EOS")), v["key"]
    assert v["signature"].startswith("SIG_K1_"), v["signature"]
print(f"fragment ok: 2 votes digest {digest[:16]}... tally {voted}/{total}")
PYEOF
check "vote scan reproduces the on-chain tally as verifier evidence"

echo
echo "cutover-fixture: PASS: $CHECKS checks green (H=$H1, finalized=$FINALIZED)"
rm -rf "$WORK"
