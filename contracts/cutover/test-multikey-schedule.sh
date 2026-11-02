#!/usr/bin/env bash
# Multi-key schedule fixture: a throwaway Leap network whose active schedule
# holds FOUR producers with four DISTINCT block-signing keys, installed the
# way a real chain does it (eosio.bios setprods -> proposed schedule ->
# activation at LIB). The single-producer handover rehearsal can never
# exercise a key-per-member roster; this proves the Leap side of one:
# the schedule activates, every member produces under its own key, and the
# header state the attach tool captures at H lists all four keys.
#
# The bios wasm is a build artifact of the proton.contracts checkout
# (BIOS_WASM / BIOS_ABI override the default sibling-checkout path).
#
# Nothing here touches mainnet.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMG="${XPR_NODEOS_IMAGE:-pulsevm-xpr-handover:local}"
PLATFORM="${XPR_PLATFORM:-linux/arm64}"
PORT="${CUTOVER_TEST_PORT:-18895}"
API="http://127.0.0.1:${PORT}"
WORK="$(mktemp -d /tmp/cutover-multikey.XXXXXX)"
NET="cutover-multikey-net"
NODES=(cutover-mk-eosio cutover-mk-a cutover-mk-b cutover-mk-c cutover-mk-d)
BIOS_WASM="${BIOS_WASM:-$REPO_ROOT/../proton.contracts/build/contracts/eosio.bios/eosio.bios.wasm}"
BIOS_ABI="${BIOS_ABI:-$REPO_ROOT/../proton.contracts/build/contracts/eosio.bios/eosio.bios.abi}"

fail() { echo "cutover-multikey: FAIL: $*" >&2; exit 1; }
pass() { echo "cutover-multikey: ok: $*"; }
CHECKS=0
check() { CHECKS=$((CHECKS + 1)); pass "$1"; }

cleanup() {
    docker rm -f "${NODES[@]}" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[[ -f "$BIOS_WASM" && -f "$BIOS_ABI" ]] || fail "eosio.bios build artifacts not found (set BIOS_WASM / BIOS_ABI)"

echo "cutover-multikey: building the probe tool..."
(cd "$REPO_ROOT" && cargo build --locked -p pulsevm_core --example make_probe_tx) \
    || fail "probe tool build failed"
PROBE="$REPO_ROOT/target/debug/examples/make_probe_tx"
[[ -x "$PROBE" ]] || fail "probe tool missing"

DEV_WIF="$(grep -o 'KEY:[A-Za-z0-9]*' "$REPO_ROOT/tools/xpr-chainbase-export/localnet/producer-config.ini" | head -1 | cut -d: -f2)"
[[ -n "$DEV_WIF" ]] || fail "fixture dev key not found"

# Four distinct schedule keys. Leap's signature-provider takes the legacy
# EOS... key form, so derive it from the compressed pubkey the probe prints.
declare -a BP_WIF BP_PUB BP_NAME BP_EOS
for i in 0 1 2 3; do
    read -r wif _ <<<"$("$PROBE" newkey)"
    BP_WIF[$i]="$wif"
    BP_PUB[$i]="$("$PROBE" pubkey "$wif")"
    BP_NAME[$i]="bp$(printf "\\$(printf '%03o' $((97 + i)))")test"
    BP_EOS[$i]="$(python3 -I - "${BP_PUB[$i]}" <<'PYEOF'
import hashlib, sys
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
raw = bytes.fromhex(sys.argv[1])
h = hashlib.new("ripemd160"); h.update(raw)
data = raw + h.digest()[:4]
n = int.from_bytes(data, "big")
out = ""
while n:
    n, r = divmod(n, 58)
    out = ALPHABET[r] + out
print("EOS" + out)
PYEOF
)"
done
echo "cutover-multikey: schedule members ${BP_NAME[*]}"

docker rm -f "${NODES[@]}" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null || fail "network create failed"

BASE_INI="plugin = eosio::chain_api_plugin
plugin = eosio::net_plugin
plugin = eosio::producer_plugin
plugin = eosio::producer_api_plugin
http-server-address = 0.0.0.0:8888
p2p-listen-endpoint = 0.0.0.0:9876
access-control-allow-origin = *
verbose-http-errors = true
resource-monitor-not-shutdown-on-threshold-exceeded = true"

# The genesis producer keeps the chain moving until the new schedule lands.
cp "$REPO_ROOT/tools/xpr-chainbase-export/localnet/producer-config.ini" "$WORK/cfg-eosio.ini"
echo "cutover-multikey: starting the genesis producer..."
docker run --detach --platform "$PLATFORM" --name "${NODES[0]}" --network "$NET" --network-alias eosio-node \
    -v "$REPO_ROOT/tools/xpr-chainbase-export/localnet/genesis.json:/config-env/genesis.json:ro" \
    -v "$WORK/cfg-eosio.ini:/config/config.ini:ro" \
    -p "127.0.0.1:${PORT}:8888" \
    "$IMG" nodeos --data-dir=/data --config-dir=/config --genesis-json=/config-env/genesis.json \
    >/dev/null || fail "genesis producer start failed"

for i in 0 1 2 3; do
    cfg="$WORK/cfg-$i.ini"
    {
        echo "$BASE_INI"
        echo "producer-name = ${BP_NAME[$i]}"
        echo "signature-provider = ${BP_EOS[$i]}=KEY:${BP_WIF[$i]}"
        echo "p2p-peer-address = eosio-node:9876"
    } >"$cfg"
    docker run --detach --platform "$PLATFORM" --name "${NODES[$((i + 1))]}" --network "$NET" \
        -p "127.0.0.1:$((PORT + 10 + i)):8888" \
        -v "$REPO_ROOT/tools/xpr-chainbase-export/localnet/genesis.json:/config-env/genesis.json:ro" \
        -v "$cfg:/config/config.ini:ro" \
        "$IMG" nodeos --data-dir=/data --config-dir=/config --genesis-json=/config-env/genesis.json \
        >/dev/null || fail "producer ${BP_NAME[$i]} start failed"
done

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
    echo "cutover-multikey: rpc $1 failed (HTTP $code): $(printf '%s' "$out" | head -c 600)" >&2
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
echo "cutover-multikey: chain $CHAIN_ID at head $HEAD_NUM"
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

# The bios imports set_proposed_producers_ex, which only resolves once
# WTMSIG_BLOCK_SIGNATURES is active. A fresh chain has only the builtin
# PREACTIVATE_FEATURE (scheduled through the producer API); every other
# feature must be preactivated by a privileged contract, so deploy the
# stock-shaped boot contract and activate through it.
feature_digest() { # $1=name
    rpc /v1/producer/get_supported_protocol_features '{}' | python3 -I -c '
import json, sys
want = sys.argv[1]
for f in json.load(sys.stdin):
    if f["specification"][0]["value"] == want:
        print(f["feature_digest"]); break
else:
    sys.exit(1)' "$1"
}
feature_active() { # $1=digest
    rpc /v1/chain/get_activated_protocol_features '{"limit":100}' \
        | python3 -I -c 'import sys; sys.exit(0 if sys.argv[1] in sys.stdin.read() else 1)' "$1"
}
wait_feature() { # $1=name $2=digest
    for _ in $(seq 1 60); do
        feature_active "$2" && return 0
        sleep 1
    done
    fail "feature $1 never activated"
}
PREACT="$(feature_digest PREACTIVATE_FEATURE)" || fail "PREACTIVATE_FEATURE not supported"
rpc /v1/producer/schedule_protocol_feature_activations "{\"protocol_features_to_activate\":[\"$PREACT\"]}" >/dev/null \
    || fail "scheduling PREACTIVATE_FEATURE failed"
wait_feature PREACTIVATE_FEATURE "$PREACT"
mk_push setcode "$CHAIN_ID" "$DEV_WIF" eosio "$SCRIPT_DIR/boot.wasm" >/dev/null
mk_push setabi "$CHAIN_ID" "$DEV_WIF" eosio "$SCRIPT_DIR/boot.abi" >/dev/null
WTMSIG="$(feature_digest WTMSIG_BLOCK_SIGNATURES)" || fail "WTMSIG_BLOCK_SIGNATURES not supported"
mk_push raw "$CHAIN_ID" "$DEV_WIF" eosio activate eosio "$WTMSIG" >/dev/null
wait_feature WTMSIG_BLOCK_SIGNATURES "$WTMSIG"
check "WTMSIG_BLOCK_SIGNATURES active"

echo "cutover-multikey: deploying eosio.bios on eosio..."
mk_push setcode "$CHAIN_ID" "$DEV_WIF" eosio "$BIOS_WASM" >/dev/null
mk_push setabi "$CHAIN_ID" "$DEV_WIF" eosio "$BIOS_ABI" >/dev/null
check "bios deployed"

# setprods(producer_authority[]): per member name u64 LE, authority variant
# 0 (block_signing_authority_v0), threshold u32 = 1, one key_weight (key
# variant 0 = K1 + 33 bytes, weight u16 = 1).
setprods_hex() {
    python3 -I - "${BP_NAME[@]}" "${BP_PUB[@]}" <<'PYEOF'
import struct, sys
rest = sys.argv[1:]
n = len(rest) // 2
names, keys = rest[:n], [bytes.fromhex(k) for k in rest[n:]]
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
out = bytearray([n])
for name, key in zip(names, keys):
    assert len(key) == 33
    out += struct.pack("<Q", name_to_u64(name)) + bytes([0]) + struct.pack("<I", 1)
    out += bytes([1]) + bytes([0]) + key + struct.pack("<H", 1)
print(bytes(out).hex())
PYEOF
}
# Leap refuses a schedule naming an account that does not exist.
for i in 0 1 2 3; do
    mk_push newaccount "$CHAIN_ID" "$DEV_WIF" "${BP_NAME[$i]}" >/dev/null
done
check "four producer accounts created"
echo "cutover-multikey: proposing the 4-producer schedule..."
mk_push raw "$CHAIN_ID" "$DEV_WIF" eosio setprods eosio "$(setprods_hex)" >/dev/null
check "setprods accepted"

# The proposal activates once its block is irreversible, then the four
# producers take over round-robin.
ACTIVE_N=0
for _ in $(seq 1 120); do
    ACTIVE_N="$(rpc /v1/chain/get_producer_schedule '{}' | python3 -c 'import json,sys; a=json.load(sys.stdin)["active"]; print(len(a["producers"]) if a["version"] >= 1 else 0)' 2>/dev/null || echo 0)"
    [[ "$ACTIVE_N" == "4" ]] && break
    sleep 2
done
[[ "$ACTIVE_N" == "4" ]] || fail "the 4-producer schedule never activated"
check "schedule v1 active with 4 producers"

# Every member must produce under its own key: wait for a full rotation.
PRODUCERS_SEEN=""
for _ in $(seq 1 90); do
    HEAD="$(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])')"
    PRODUCERS_SEEN="$(python3 -I - "$API" "$HEAD" <<'PYEOF'
import json, sys, urllib.request
api, head = sys.argv[1], int(sys.argv[2])
seen = set()
for n in range(max(1, head - 120), head + 1, 6):
    req = urllib.request.Request(api + "/v1/chain/get_block", data=json.dumps({"block_num_or_id": str(n)}).encode(),
                                 headers={"Content-Type": "application/json", "Host": "0.0.0.0:8888"})
    seen.add(json.load(urllib.request.urlopen(req, timeout=10))["producer"])
print(" ".join(sorted(seen - {"eosio"})))
PYEOF
)"
    [[ "$(wc -w <<<"$PRODUCERS_SEEN" | tr -d ' ')" == "4" ]] && break
    sleep 3
done
echo "cutover-multikey: producers seen: $PRODUCERS_SEEN"
[[ "$(wc -w <<<"$PRODUCERS_SEEN" | tr -d ' ')" == "4" ]] || fail "not every scheduled member produced: [$PRODUCERS_SEEN]"
check "all four members produced blocks"

# LIB must advance under the 4-member schedule (3 of 4 confirmations).
# LIB moves in bursts (12-block turns across four producers), so poll
# for an increase instead of sampling one fixed window.
LIB1="$(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["last_irreversible_block_num"])')"
LIB2="$LIB1"
for _ in $(seq 1 45); do
    sleep 2
    LIB2="$(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["last_irreversible_block_num"])')"
    [[ "$LIB2" -gt "$LIB1" ]] && break
done
[[ "$LIB2" -gt "$LIB1" ]] || fail "LIB stalled under the 4-member schedule for 90s ($LIB1 -> $LIB2)"
check "LIB advances ($LIB1 -> $LIB2)"

# The header state is what the attach tool captures at H: its active
# schedule must hold exactly the four distinct keys.
HEAD="$(rpc /v1/chain/get_info '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["head_block_num"])')"
python3 -I - "$API" "$HEAD" "${BP_NAME[*]}" "${BP_PUB[*]}" <<'PYEOF'
import json, sys, urllib.request
api, head = sys.argv[1], int(sys.argv[2])
names, pubs = sys.argv[3].split(), sys.argv[4].split()
req = urllib.request.Request(api + "/v1/chain/get_block_header_state", data=json.dumps({"block_num_or_id": str(head)}).encode(),
                             headers={"Content-Type": "application/json", "Host": "0.0.0.0:8888"})
hs = json.load(urllib.request.urlopen(req, timeout=10))
prods = hs["active_schedule"]["producers"]
got = {p["producer_name"]: p for p in prods}
assert sorted(got) == sorted(names), (sorted(got), sorted(names))
assert len(set(json.dumps(p["authority"], sort_keys=True) for p in prods)) == 4, "schedule keys are not distinct"
print("header-state schedule version", hs["active_schedule"]["version"], "members", sorted(got))
PYEOF
check "header state lists four distinct member keys"
# Snapshot probe: which nodes can complete create_snapshot once the schedule
# has moved off the genesis producer?
if [[ -n "${SNAPSHOT_PROBE:-}" ]]; then
    for target in "$PORT" "$((PORT + 10))" "$((PORT + 11))" "$((PORT + 12))" "$((PORT + 13))"; do
        code="$(curl --silent --max-time 40 -o "$WORK/snap-$target.json" -w '%{http_code}' -X POST "http://127.0.0.1:$target/v1/producer/create_snapshot" \
            -H 'Content-Type: application/json' -H 'Host: 0.0.0.0:8888' -d '{}' 2>/dev/null || true)"
        echo "cutover-multikey: snapshot port $target -> http ${code:-none}: $(head -c 120 "$WORK/snap-$target.json" 2>/dev/null)"
    done
fi
# Optional: keep the producer's block log for offline replay checks.
if [[ -n "${KEEP_BLOCKS_DIR:-}" ]]; then
    rm -rf "$KEEP_BLOCKS_DIR"
    docker cp "${NODES[0]}:/data/blocks" "$KEEP_BLOCKS_DIR" >/dev/null || fail "block log copy failed"
    echo "cutover-multikey: block log kept at $KEEP_BLOCKS_DIR"
fi
echo "cutover-multikey: PASS: $CHECKS checks green"
