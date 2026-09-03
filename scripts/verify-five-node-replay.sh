#!/usr/bin/env bash
# Verify that all five live runner nodes have booted PulseVM, converged on the
# same head, and can independently decode that head block. This is the live
# replay/convergence gate; it intentionally uses the node RPCs rather than the
# runner's in-memory status only.
#
# Usage:
#   scripts/verify-five-node-replay.sh [runner-endpoint] [chain-id]
#
# The runner must already be serving control RPCs. Set
# METAL_NETWORK_RUNNER_PATH to override the bundled runner binary.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${METAL_NETWORK_RUNNER_PATH:-${REPO_ROOT}/../metal-network-runner/bin/metal-network-runner}"
RUNNER_ENDPOINT="${1:-${METAL_NETWORK_RUNNER_ENDPOINT:-localhost:8080}}"
EXPECTED_CHAIN_ID="${2:-${PULSEVM_CHAIN_ID:-}}"
TIMEOUT="${PULSEVM_RPC_TIMEOUT:-10}"
REPORT="${PULSEVM_FIVE_NODE_REPORT:-}"

if [[ ! -x "$RUNNER" ]]; then
  echo "error: metal-network-runner is not executable: $RUNNER" >&2
  exit 1
fi
command -v curl >/dev/null 2>&1 || { echo "error: curl is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 1; }

echo "==> Waiting for the five-node cluster and PulseVM VM"
"$RUNNER" control wait-for-healthy --endpoint="$RUNNER_ENDPOINT" --request-timeout=10m >/dev/null

RPC_TEXT=$("$RUNNER" control list-rpcs --endpoint="$RUNNER_ENDPOINT")
# The runner's human CLI adds timestamp/color prefixes, so normalize those
# before extracting the stable RPC lines. (The URLs themselves are unchanged.)
RPC_TEXT_CLEAN=$(printf '%s\n' "$RPC_TEXT" | sed $'s/\033\\[[0-9;]*m//g')
CHAIN_ID=$(printf '%s\n' "$RPC_TEXT_CLEAN" | sed -nE 's/.*Blockchain ID: ([A-Za-z0-9]+).*/\1/p' | head -1)
if [[ -z "$CHAIN_ID" ]]; then
  echo "error: runner returned no custom blockchain RPCs" >&2
  printf '%s\n' "$RPC_TEXT" >&2
  exit 1
fi
if [[ -n "$EXPECTED_CHAIN_ID" && "$CHAIN_ID" != "$EXPECTED_CHAIN_ID" ]]; then
  echo "error: runner chain id $CHAIN_ID does not match expected $EXPECTED_CHAIN_ID" >&2
  exit 1
fi

RPCS=()
while IFS= read -r rpc; do
  [[ -n "$rpc" ]] && RPCS+=("$rpc")
done < <(printf '%s\n' "$RPC_TEXT_CLEAN" | sed -nE 's/.*node[0-9]+: (https?:\/\/[^[:space:]]+).*/\1/p' | sort)
if [[ "${#RPCS[@]}" -ne 5 ]]; then
  echo "error: expected five custom-chain RPCs, found ${#RPCS[@]}" >&2
  printf '%s\n' "$RPC_TEXT" >&2
  exit 1
fi

tmp_report="$(mktemp "${TMPDIR:-/tmp}/pulsevm-five-node-replay.XXXXXX.json")"
trap 'rm -f -- "$tmp_report"' EXIT
heads='[]'
for rpc in "${RPCS[@]}"; do
  info=$(curl --fail --silent --show-error --max-time "$TIMEOUT" \
    -X POST "$rpc" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":[]}')
  if ! jq -e '.result.head_block_num and (.result.head_block_id | type == "string")' >/dev/null <<<"$info"; then
    echo "error: $rpc did not return a valid pulsevm.getInfo response" >&2
    printf '%s\n' "$info" >&2
    exit 1
  fi
  head_num=$(jq -er '.result.head_block_num' <<<"$info")
  head_id=$(jq -er '.result.head_block_id' <<<"$info")
  block=$(curl --fail --silent --show-error --max-time "$TIMEOUT" \
    -X POST "$rpc" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"pulsevm.getBlock\",\"params\":[\"$head_num\"]}")
  if ! jq -e --arg id "$head_id" '.result.id == $id' >/dev/null <<<"$block"; then
    echo "error: $rpc could not decode head block $head_num/$head_id" >&2
    printf '%s\n' "$block" >&2
    exit 1
  fi
  heads=$(jq --arg rpc "$rpc" --arg id "$head_id" --argjson num "$head_num" \
    '. + [{rpc: $rpc, head_block_num: $num, head_block_id: $id}]' <<<"$heads")
done

unique_heads=$(jq '[.[].head_block_id] | unique | length' <<<"$heads")
if [[ "$unique_heads" != 1 ]]; then
  echo "error: five nodes are not on one head" >&2
  jq . <<<"$heads" >&2
  exit 1
fi
head_num=$(jq -er '.[0].head_block_num' <<<"$heads")
head_id=$(jq -er '.[0].head_block_id' <<<"$heads")
jq -n --arg chain_id "$CHAIN_ID" --arg head_id "$head_id" --argjson head_num "$head_num" \
  --argjson nodes "$heads" \
  '{chain_id:$chain_id, node_count:($nodes|length), head_block_num:$head_num, head_block_id:$head_id, nodes:$nodes, status:"passed"}' \
  >"$tmp_report"
if [[ -n "$REPORT" ]]; then
  mkdir -p "$(dirname "$REPORT")"
  cp "$tmp_report" "$REPORT"
fi

echo "five-node live replay passed: chain=$CHAIN_ID nodes=5 head=$head_num/$head_id"
[[ -n "$REPORT" ]] && echo "report=$REPORT"
