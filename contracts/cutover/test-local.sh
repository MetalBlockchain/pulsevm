#!/usr/bin/env bash
# Fixture test for the cutover ceremony contract on a throwaway single-node
# Leap chain. Freezes an explicit 4-member schedule via init (one member,
# one vote — no vote weights anywhere) and exercises every vote path:
# outsider rejection, wrong-height digest, double vote, boundary quorum
# (1 and 2 of 4 must NOT finalize, 3 of 4 must, at strict 2/3+1),
# post-finalize and post-vote re-init rejection, plus an independent Python
# reimplementation of the declaration digest and the count tally that must
# match the contract bit-for-bit. The freeze window (init_time stamp,
# re-init re-stamp) is asserted as plumbing; the 7-day expiry itself is
# not exercised here — no test chain can wait it out, and time-travel
# would invalidate the fixture — so expiry is covered by the voter
# predicate unit tests (same constant, same comparison) plus the boundary
# that a live freeze always carries a sane init_time.
#
# Nothing here touches mainnet.
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

# Four BPs with no weights anywhere: the frozen schedule is a count
# quorum, so 1 and 2 of 4 must not finalize and 3 of 4 must.
declare -a BP_WIF BP_PUB BP_NAME
for i in 0 1 2 3; do
    read -r wif _ <<<"$("$PROBE" newkey)"
    BP_WIF[$i]="$wif"
    BP_PUB[$i]="$("$PROBE" pubkey "$wif")"
    BP_NAME[$i]="bp$(printf '%s' abcd | cut -c$((i + 1)))test"
done
echo "cutover-fixture: BPs ${BP_NAME[*]}"

echo "cutover-fixture: deploying contracts..."
mk_push setcode "$CHAIN_ID" "$DEV_WIF" cutover "$SCRIPT_DIR/cutover.wasm" >/dev/null
mk_push setabi "$CHAIN_ID" "$DEV_WIF" cutover "$SCRIPT_DIR/cutover.abi" >/dev/null
check "contracts deployed"

# Pack the init action: h LE + chain + schedule_version LE + member count
# varuint + per member (name u64 LE + key variant varuint(0=K1) + 33 bytes).
# The schedule is explicit — the contract reads no on-chain table — and the
# frozen version is the live active schedule version at freeze time.
init_hex() { # $1=H -> hex
    python3 - "$1" "$CHAIN_ID" "$SCHED_VERSION" "${BP_NAME[@]}" "${BP_PUB[@]}" <<'PYEOF'
import struct, sys
h, chain, version = int(sys.argv[1]), bytes.fromhex(sys.argv[2]), int(sys.argv[3])
rest = sys.argv[4:]
n = len(rest) // 2
names, keys = rest[:n], [bytes.fromhex(k) for k in rest[n:]]
def char_to_symbol(c):
    if "a" <= c <= "z":
        return ord(c) - ord("a") + 6
    if "1" <= c <= "5":
        return ord(c) - ord("1") + 1
    return 0
def name_to_u64(s):
    assert len(s) <= 13, s
    v = 0
    for i in range(12):
        v = (v << 5) | char_to_symbol(s[i] if i < len(s) else ".")
    v = (v << 4) | (char_to_symbol(s[12]) if len(s) == 13 else 0)
    return v
def varuint(v):
    out = b""
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])
out = bytearray(struct.pack("<I", h) + chain + struct.pack("<I", version))
out += varuint(len(names))
for name, key in zip(names, keys):
    assert len(key) == 33, len(key)
    out += struct.pack("<Q", name_to_u64(name)) + varuint(0) + key
print(bytes(out).hex())
PYEOF
}

SCHED_VERSION="$(rpc /v1/chain/get_producer_schedule '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["active"]["version"])')"
echo "cutover-fixture: freezing the 4-member schedule (version $SCHED_VERSION)..."
H1=$(( $(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])') + 20 ))
echo "cutover-fixture: init H=$H1..."
mk_push raw "$CHAIN_ID" "$DEV_WIF" cutover init cutover "$(init_hex "$H1")" >/dev/null
read -r FROZEN_H FROZEN_VERSION VOTED TOTAL FINALIZED DIGEST INIT_US <<<"$(
    table_rows cutover cutover ceremony | python3 -c '
import json,sys
c = json.load(sys.stdin)[0]
print(c["h"], c["schedule_version"], c["voted_weight"], c["total_weight"], int(c["finalized"]), c["declaration_digest"], c["init_time"])' )"
# Frozen roster for the tool-built votes: unit weights as decimal strings.
table_rows cutover cutover members | python3 -c "
import json,sys
rows = json.load(sys.stdin)
members = [{'producer': r['producer'], 'key': r['key'], 'weight': str(int(r['weight']))} for r in rows]
json.dump(members, open('$WORK/members.json', 'w'))
print(len(rows))"
COUNT="$(python3 -c "import json; print(len(json.load(open('$WORK/members.json'))))")"
echo "cutover-fixture: frozen $COUNT members"
[[ "$FROZEN_H" == "$H1" ]] || fail "init froze wrong H"
[[ "$FROZEN_VERSION" == "$SCHED_VERSION" ]] || fail "init froze wrong schedule version"
[[ "$FINALIZED" == "0" ]] || fail "fresh ceremony finalized"
[[ "$COUNT" == "4" ]] || fail "init must freeze exactly the 4 schedule members"
[[ "$TOTAL" == "4" ]] || fail "frozen total must be the 4-member count"
[[ "$VOTED" == "0" ]] || fail "fresh ceremony has votes"
check "init froze the 4-member schedule at H=$H1 (version $SCHED_VERSION)"
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
mk_push raw "$CHAIN_ID" "$DEV_WIF" cutover init cutover "$(init_hex "$H2")" >/dev/null
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

# Independent reimplementation of the declaration digest and the count
# tally: the contract must match this Python bit-for-bit (digest) and in
# value (tally), or the votes below fail. Every member weighs 1, so the
# digest binds unit weights and the tally is a member count.
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
assert all(int(m["weight"]) == 1 for m in members), "every frozen member must weigh 1"
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

assert int(sys.argv[5]) == len(members) == 4, f"tally mismatch: contract {sys.argv[5]}"
# Count quorum over 4: 1 and 2 of 4 must not finalize (3 and 6 <= 8),
# 3 of 4 must (9 > 8) — the 15-of-21 shape at fixture scale.
assert 1 * 3 <= 4 * 2, "1 of 4 must not finalize"
assert 2 * 3 <= 4 * 2, "2 of 4 must not finalize"
assert 3 * 3 > 4 * 2, "3 of 4 must finalize"
print("quorum boundary confirmed: 3 of 4 to finalize")
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
do_vote_late() { do_vote 3; }
do_reinit_locked() {
    mk_push raw "$CHAIN_ID" "$DEV_WIF" cutover init cutover "$(init_hex "$H3")"
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

echo "cutover-fixture: first valid vote (1 of 4: must NOT finalize)..."
TX1="$(do_vote 0)"
echo "cutover-fixture: vote tx $TX1"
read -r VOTED FINALIZED <<<"$(table_rows cutover cutover ceremony | python3 -c '
import json,sys
c = json.load(sys.stdin)[0]
print(c["voted_weight"], int(c["finalized"]))')"
[[ "$FINALIZED" == "0" ]] || fail "1 of 4 finalized"
check "first vote counted, tally open"

echo "cutover-fixture: double vote must fail..."
expect_fail "double vote" "already voted" do_vote_again

echo "cutover-fixture: second vote (2 of 4, exactly half: must NOT finalize)..."
TX2="$(do_vote 1)"
echo "cutover-fixture: vote tx $TX2"
read -r VOTED FINALIZED <<<"$(table_rows cutover cutover ceremony | python3 -c '
import json,sys
c = json.load(sys.stdin)[0]
print(c["voted_weight"], int(c["finalized"]))')"
[[ "$FINALIZED" == "0" ]] || fail "2 of 4 finalized at exactly half"
check "second vote counted, tally still open"

echo "cutover-fixture: third vote (3 of 4: must finalize)..."
TX3="$(do_vote 2)"
echo "cutover-fixture: vote tx $TX3"
read -r VOTED FINALIZED <<<"$(table_rows cutover cutover ceremony | python3 -c '
import json,sys
c = json.load(sys.stdin)[0]
print(c["voted_weight"], int(c["finalized"]))')"
[[ "$FINALIZED" == "1" ]] || fail "3 of 4 did not finalize"
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
grep -q "schedule_version=$SCHED_VERSION" "$SCAN_LOG" || fail "scanner must attest the unanimous schedule version"
python3 - "$WORK/fragment.json" "$WORK/declaration.json" "$DIGEST" "$TOTAL" "$VOTED" "$H1" "${BP_NAME[0]}" "${BP_NAME[1]}" "${BP_NAME[2]}" <<'PYEOF'
import json, sys
frag = json.load(open(sys.argv[1]))
decl = json.load(open(sys.argv[2]))
digest, total, voted, h = (sys.argv[3], int(sys.argv[4]),
    int(sys.argv[5]), int(sys.argv[6]))
quorum = sorted(sys.argv[7:10])
assert frag["contract"] == "cutover", frag["contract"]
assert frag["declaration_digest"] == digest, "fragment digest must equal the frozen digest"
assert int(frag["total_weight"]) == total == 4, "fragment total must equal the 4-member roster"
assert int(frag["voted_weight"]) == voted == 3, "fragment tally must equal the on-chain tally"
assert frag["finalized"] is True, "fragment must capture a completed tally"
assert frag["finalized_block"] < h, "finality must predate H"
assert len(frag["votes"]) == 3, f"want exactly the 3 counted votes, got {len(frag['votes'])}"
names = sorted(v["producer"] for v in frag["votes"])
assert names == quorum, f"fragment voters {names} are not the quorum"
# The exporter-built declaration carries the frozen roster plus the scanned
# signatures; its digest is the ceremony digest by construction.
assert decl["last_height"] == h, "declaration must target H"
assert len(decl["signatures"]) == 3, "declaration must carry the 3 vote signatures"
assert decl["validator_set"] and len(decl["validator_set"]) == 4
for v in frag["votes"]:
    assert v["block"] < h, f"vote block {v['block']} must predate H={h}"
    # Leap renders the frozen K1 keys in legacy EOS form here; the Rust
    # verifier parses both PUB_K1_ and EOS forms.
    assert v["key"].startswith(("PUB_K1_", "EOS")), v["key"]
    assert v["signature"].startswith("SIG_K1_"), v["signature"]
print(f"fragment ok: 3 votes digest {digest[:16]}... tally {voted}/{total}")
PYEOF
check "vote scan reproduces the on-chain tally as verifier evidence"

echo
echo "cutover-fixture: PASS: $CHECKS checks green (H=$H1, finalized=$FINALIZED)"
rm -rf "$WORK"
