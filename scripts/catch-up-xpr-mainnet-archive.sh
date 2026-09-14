#!/usr/bin/env bash
# Build a fixed, genesis-to-LIB XPR Mainnet block corpus from a current nodeos
# blocks/state archive and P2P catch-up. The resulting blocks.log is suitable
# for xpr_blocklog_replay; the report pins the exact terminal block.
set -euo pipefail

BLOCKS_URL="${XPR_BLOCKS_URL:-https://snapshots.bloxprod.io/mainnet/blocks.tar.gz}"
STATE_URL="${XPR_STATE_URL:-https://snapshots.bloxprod.io/mainnet/state.tar.gz}"
REFERENCE_API="${XPR_REFERENCE_API:-https://xpr-mainnet-api.bloxprod.io}"
WORK_ROOT="${XPR_CORPUS_WORK_ROOT:-/data/xpr-mainnet-current-download}"
NODE_ROOT="${XPR_CORPUS_NODE_ROOT:-/data/xpr-mainnet-current-node}"
NODEOS="${XPR_NODEOS:-/data/leap-5.0.3/build/programs/nodeos/nodeos}"
CONFIG_DIR="${XPR_CONFIG_DIR:-/data/xpr-mainnet-source/config}"
HTTP_ENDPOINT="${XPR_LOCAL_HTTP_ENDPOINT:-127.0.0.1:8888}"
P2P_ENDPOINT="${XPR_LOCAL_P2P_ENDPOINT:-127.0.0.1:9876}"
TIMEOUT_SECONDS="${XPR_CATCHUP_TIMEOUT_SECONDS:-86400}"

for command in curl jq tar; do
  command -v "$command" >/dev/null || {
    echo "error: required command is missing: $command" >&2
    exit 1
  }
done
[[ -x "$NODEOS" ]] || { echo "error: nodeos is not executable: $NODEOS" >&2; exit 1; }
[[ -d "$CONFIG_DIR" ]] || { echo "error: nodeos config directory is missing: $CONFIG_DIR" >&2; exit 1; }
[[ "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] || {
  echo "error: XPR_CATCHUP_TIMEOUT_SECONDS must be positive" >&2
  exit 1
}

mkdir -p "$WORK_ROOT" "$NODE_ROOT"

download() {
  local url="$1"
  local output="$2"
  local expected actual
  expected="$(curl -fsSI "$url" | tr -d '\r' | awk '
    tolower($1) == "content-length:" { value=$2 }
    END { print value }
  ')"
  [[ "$expected" =~ ^[1-9][0-9]*$ ]] || {
    echo "error: cannot determine content length for $url" >&2
    return 1
  }
  actual=0
  [[ -f "$output" ]] && actual="$(stat -c %s "$output")"
  if ((actual == expected)); then
    echo "==> Reusing complete download $output"
    return
  fi
  if ((actual > expected)); then
    echo "error: $output is larger than its remote object" >&2
    return 1
  fi
  echo "==> Downloading $url ($actual/$expected bytes present)"
  curl --fail --location --retry 20 --retry-delay 10 \
    --continue-at - --output "$output" "$url"
  actual="$(stat -c %s "$output")"
  [[ "$actual" == "$expected" ]] || {
    echo "error: incomplete download $output ($actual/$expected bytes)" >&2
    return 1
  }
}

STATE_ARCHIVE="$WORK_ROOT/state.tar.gz"
BLOCKS_ARCHIVE="$WORK_ROOT/blocks.tar.gz"
download "$STATE_URL" "$STATE_ARCHIVE"
if [[ ! -s "$WORK_ROOT/state-extracted" || ! -s "$NODE_ROOT/state/shared_memory.bin" ]]; then
  echo "==> Extracting matching nodeos state"
  tar -xzf "$STATE_ARCHIVE" -C "$NODE_ROOT"
  printf 'complete\n' >"$WORK_ROOT/state-extracted"
else
  echo "==> Reusing extracted nodeos state"
fi

download "$BLOCKS_URL" "$BLOCKS_ARCHIVE"
if [[ ! -s "$WORK_ROOT/blocks-extracted" || ! -s "$NODE_ROOT/blocks/blocks.log" || ! -s "$NODE_ROOT/blocks/blocks.index" ]]; then
  echo "==> Extracting complete nodeos block corpus"
  tar -xzf "$BLOCKS_ARCHIVE" -C "$NODE_ROOT"
  printf 'complete\n' >"$WORK_ROOT/blocks-extracted"
else
  echo "==> Reusing extracted nodeos block corpus"
fi

TARGET_FILE="$WORK_ROOT/catchup-target.json"
if [[ ! -s "$TARGET_FILE" ]]; then
  echo "==> Pinning an irreversible Mainnet catch-up target"
  curl -fsS "$REFERENCE_API/v1/chain/get_info" | jq -e '{
    chain_id,
    target_block_num: .last_irreversible_block_num,
    target_block_id: .last_irreversible_block_id,
    captured_head_block_num: .head_block_num
  }' >"$TARGET_FILE"
fi
target_num="$(jq -er '.target_block_num' "$TARGET_FILE")"
target_id="$(jq -er '.target_block_id' "$TARGET_FILE")"
[[ "$target_num" =~ ^[1-9][0-9]*$ && "$target_id" =~ ^[[:xdigit:]]{64}$ ]] || {
  echo "error: invalid catch-up target: $TARGET_FILE" >&2
  exit 1
}

NODEOS_LOG="$WORK_ROOT/nodeos-catchup.log"
echo "==> Starting nodeos catch-up through irreversible block $target_num"
"$NODEOS" \
  --data-dir "$NODE_ROOT" \
  --config-dir "$CONFIG_DIR" \
  --chain-state-db-size-mb 16384 \
  --http-server-address "$HTTP_ENDPOINT" \
  --p2p-listen-endpoint "$P2P_ENDPOINT" \
  --sync-fetch-span 2000 \
  --plugin eosio::chain_api_plugin \
  --p2p-peer-address xpr-mainnet-p2p.bloxprod.io:9876 \
  --p2p-peer-address p2p-protonmain.saltant.io:9876 \
  --p2p-peer-address proton.protonuk.io:9876 \
  >"$NODEOS_LOG" 2>&1 &
nodeos_pid=$!
printf '%s\n' "$nodeos_pid" >"$WORK_ROOT/nodeos-catchup.pid"

shutdown_nodeos() {
  if kill -0 "$nodeos_pid" 2>/dev/null; then
    kill -TERM "$nodeos_pid" 2>/dev/null || true
    wait "$nodeos_pid" 2>/dev/null || true
  fi
}
trap shutdown_nodeos EXIT INT TERM

deadline=$((SECONDS + TIMEOUT_SECONDS))
local_lib=0
while ((SECONDS < deadline)); do
  if ! kill -0 "$nodeos_pid" 2>/dev/null; then
    wait "$nodeos_pid" || true
    tail -n 100 "$NODEOS_LOG" >&2 || true
    echo "error: nodeos exited before reaching block $target_num" >&2
    exit 1
  fi
  info="$(curl -fsS --max-time 5 "http://$HTTP_ENDPOINT/v1/chain/get_info" 2>/dev/null || true)"
  local_lib="$(jq -r '.last_irreversible_block_num // 0' <<<"$info" 2>/dev/null || printf 0)"
  if [[ "$local_lib" =~ ^[0-9]+$ ]] && ((local_lib >= target_num)); then
    break
  fi
  sleep 5
done
((local_lib >= target_num)) || {
  echo "error: nodeos did not reach irreversible block $target_num within ${TIMEOUT_SECONDS}s" >&2
  exit 1
}

actual_id="$(curl -fsS --max-time 30 \
  -H 'content-type: application/json' \
  --data "{\"block_num_or_id\":$target_num}" \
  "http://$HTTP_ENDPOINT/v1/chain/get_block" | jq -er '.id')"
[[ "$actual_id" == "$target_id" ]] || {
  echo "error: local block $target_num is $actual_id, expected $target_id" >&2
  exit 1
}

shutdown_nodeos
trap - EXIT INT TERM
jq -n \
  --argjson terminal_block_num "$target_num" \
  --arg terminal_block_id "$target_id" \
  --arg blocks_log "$NODE_ROOT/blocks/blocks.log" \
  --arg blocks_index "$NODE_ROOT/blocks/blocks.index" \
  '{status:"complete", terminal_block_num:$terminal_block_num,
    terminal_block_id:$terminal_block_id, blocks_log:$blocks_log,
    blocks_index:$blocks_index}' | tee "$WORK_ROOT/corpus-report.json"
