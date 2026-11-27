#!/usr/bin/env bash
# One equal-weight validator among a large committee must still advance when
# another one of them goes dark. MetalGo's benching cap is
# (1 - alpha_confidence/k) / 3; Paul's rehearsal report measured this as
# 8.33% at five equal validators, so a 20%-weight validator could never be
# benched and the other four stalled when it went silent. At 21 equal
# validators the cap is about 4.76%, just above a 21st's own ~4.76% weight.
# This drives that scenario against a real cluster instead of computing it
# on paper: kill one validator, require every other node's RPC to still
# answer, and require all of them to keep advancing within a bounded window.
#
# Usage: scripts/verify-benching-at-scale.sh [runner-endpoint]
#
# PULSEVM_BENCHING_VICTIM_PATTERN selects which node's process to kill (a
# pgrep -f pattern matched against the node's own data-dir path, e.g.
# "node21/configs"); defaults to the last node of a 21-node cluster.
# PULSEVM_BENCHING_WAIT_SECS bounds how long the survivors get to prove they
# are still making progress (default 90s).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${METAL_NETWORK_RUNNER_PATH:-${REPO_ROOT}/../metal-network-runner/bin/metal-network-runner}"
RUNNER_ENDPOINT="${1:-${METAL_NETWORK_RUNNER_ENDPOINT:-localhost:8080}}"
VICTIM_PATTERN="${PULSEVM_BENCHING_VICTIM_PATTERN:-node21/configs}"
WAIT_SECS="${PULSEVM_BENCHING_WAIT_SECS:-90}"

if [[ ! -x "$RUNNER" ]]; then
  echo "error: metal-network-runner is not executable: $RUNNER" >&2
  exit 1
fi
command -v curl >/dev/null 2>&1 || { echo "error: curl is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 1; }

echo "==> Reading the custom-chain RPCs from the runner"
RPC_TEXT=$("$RUNNER" control list-rpcs --endpoint="$RUNNER_ENDPOINT")
RPC_TEXT_CLEAN=$(printf '%s\n' "$RPC_TEXT" | sed $'s/\033\\[[0-9;]*m//g')
RPCS=()
while IFS= read -r rpc; do
  [[ -n "$rpc" ]] && RPCS+=("$rpc")
done < <(printf '%s\n' "$RPC_TEXT_CLEAN" | sed -nE 's/.*node[0-9]+: (https?:\/\/[^[:space:]]+).*/\1/p' | sort)
[[ "${#RPCS[@]}" -ge 2 ]] || { echo "error: fewer than two custom-chain RPCs found" >&2; printf '%s\n' "$RPC_TEXT" >&2; exit 1; }
echo "==> ${#RPCS[@]} node RPCs found"

head_of() { # $1=rpc, echoes the head block num or "0" on any failure
  curl --fail --silent --max-time 10 -X POST "$1" \
    -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":[]}' 2>/dev/null \
    | jq -er '.result.head_block_num' 2>/dev/null || echo 0
}

echo "==> Killing one validator (pattern: $VICTIM_PATTERN)"
victim="$(pgrep -f "$VICTIM_PATTERN" | head -1 || true)"
[[ -n "$victim" ]] || { echo "error: no process matching '$VICTIM_PATTERN' found" >&2; exit 1; }
kill -9 "$victim"
echo "==> killed pid $victim"

# Every RPC except the one just killed must still answer. A node that stops
# answering here means more than one validator is down, which proves nothing
# about benching.
survivors=()
for rpc in "${RPCS[@]}"; do
  if curl --fail --silent --max-time 5 -X POST "$rpc" -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":[]}' >/dev/null 2>&1; then
    survivors+=("$rpc")
  fi
done
if [[ "${#survivors[@]}" -ne $((${#RPCS[@]} - 1)) ]]; then
  echo "error: expected exactly one node down, found ${#survivors[@]} of ${#RPCS[@]} still answering" >&2
  exit 1
fi
echo "==> ${#survivors[@]} of ${#RPCS[@]} nodes still answering after the kill"

echo "==> waiting up to ${WAIT_SECS}s for every surviving node to advance past its current head"
start_heads=()
for rpc in "${survivors[@]}"; do
  start_heads+=("$(head_of "$rpc")")
done
deadline=$((SECONDS + WAIT_SECS))
advanced=0
while [[ "$SECONDS" -lt "$deadline" ]]; do
  all_advanced=1
  for i in "${!survivors[@]}"; do
    now="$(head_of "${survivors[$i]}")"
    if [[ "$now" -le "${start_heads[$i]}" ]]; then
      all_advanced=0
    fi
  done
  if [[ "$all_advanced" == 1 ]]; then
    advanced=1
    break
  fi
  sleep 3
done
if [[ "$advanced" != 1 ]]; then
  echo "error: the surviving committee did not advance within ${WAIT_SECS}s after one validator was killed -- this is the stall Paul's rehearsal measured at five equal validators (8.33% benching cap vs a 20% validator); it must not reproduce at this committee size" >&2
  exit 1
fi
echo "benching-at-scale passed: all ${#survivors[@]} surviving nodes advanced after one validator was killed"
