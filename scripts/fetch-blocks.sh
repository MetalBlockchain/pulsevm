#!/usr/bin/env bash
# Fetch a range of real testnet blocks from the PulseVM RPC into JSON fixture
# files, one per block (NNNNNNNN.json), for replay against the Rust database.
#
#   scripts/fetch-blocks.sh <from> <to> [out_dir] [rpc_url]
#
# Then run the replay:
#   PULSEVM_RPC_BLOCKS_DIR=<out_dir> cargo test -p pulsevm_core \
#     replay_testnet_blocks -- --ignored --nocapture
set -euo pipefail

FROM="${1:?usage: fetch-blocks.sh <from> <to> [out_dir] [rpc_url]}"
TO="${2:?usage: fetch-blocks.sh <from> <to> [out_dir] [rpc_url]}"
OUT="${3:-/tmp/rpcblocks}"
RPC="${4:-https://a-chain-alpine-rpc.metalblockchain.org/rpc}"

mkdir -p "$OUT"
for ((n=FROM; n<=TO; n++)); do
  f=$(printf "%s/%08d.json" "$OUT" "$n")
  curl -s --max-time 30 -X POST "$RPC" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$n,\"method\":\"pulsevm.getBlock\",\"params\":{\"block_num_or_id\":\"$n\"}}" \
    > "$f"
  if ! grep -q '"result"' "$f"; then
    echo "fetch failed at block $n:" >&2; head -c 200 "$f" >&2; echo >&2; exit 1
  fi
  (( n % 100 == 0 )) && echo "fetched $n/$TO"
done
echo "fetched blocks $FROM..$TO into $OUT"
