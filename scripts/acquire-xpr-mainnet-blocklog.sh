#!/usr/bin/env bash
# Acquire XPR Mainnet's canonical irreversible blocks.log from genesis.
set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ACTION="${1:-start}"
readonly SOURCE_ROOT="${XPR_SOURCE_DIR:-/data/xpr-mainnet-source}"
readonly DATA_DIR="$SOURCE_ROOT/data"
readonly CONFIG_DIR="$SOURCE_ROOT/config"
readonly BLOCKS_DIR="$DATA_DIR/blocks"
readonly PID_FILE="$SOURCE_ROOT/nodeos.pid"
readonly LOG_FILE="$SOURCE_ROOT/nodeos.log"
readonly GENESIS="${XPR_GENESIS_PATH:-$REPO_ROOT/tools/xpr-chainbase-export/xpr-mainnet-genesis.json}"

fail() {
  echo "error: $*" >&2
  exit 1
}

find_nodeos() {
  local candidate
  if [[ -n "${XPR_NODEOS:-}" ]]; then
    printf '%s\n' "$XPR_NODEOS"
    return
  fi
  for candidate in \
    /data/leap-5.0.3/build/programs/nodeos/nodeos \
    "$REPO_ROOT/../leap-5.0.3/build/programs/nodeos/nodeos"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  fail "set XPR_NODEOS to the pinned Leap 5.0.3 nodeos binary"
}

pid_is_nodeos() {
  local pid="${1:-}"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  tr '\0' ' ' <"/proc/$pid/cmdline" | grep -F -- "--data-dir=$DATA_DIR" >/dev/null
}

start_nodeos() {
  [[ "$(uname -s)" == "Linux" ]] || fail "XPR source acquisition requires Linux"
  [[ -s "$GENESIS" ]] || fail "XPR genesis not found: $GENESIS"
  local nodeos pid
  nodeos="$(find_nodeos)"
  [[ -x "$nodeos" ]] || fail "nodeos is not executable: $nodeos"
  if [[ -s "$PID_FILE" ]] && pid_is_nodeos "$(<"$PID_FILE")"; then
    fail "XPR nodeos is already running with PID $(<"$PID_FILE")"
  fi

  mkdir -p "$DATA_DIR" "$CONFIG_DIR"
  local genesis_args=()
  if [[ ! -s "$BLOCKS_DIR/blocks.log" ]]; then
    genesis_args+=("--genesis-json=$GENESIS")
  fi
  local peers=(
    api.protonnz.com:9876
    proton.protonuk.io:9876
    proton.p2p.eosusa.io:9879
    proton.cryptolions.io:9876
    protonp2p.eoscafeblock.com:9130
  )
  local peer_args=()
  for peer in "${peers[@]}"; do
    peer_args+=("--p2p-peer-address=$peer")
  done

  echo "==> Starting pinned nodeos against XPR Mainnet from genesis"
  nohup "$nodeos" \
    "--data-dir=$DATA_DIR" \
    "--config-dir=$CONFIG_DIR" \
    "${genesis_args[@]}" \
    --plugin=eosio::chain_plugin \
    --plugin=eosio::chain_api_plugin \
    --plugin=eosio::http_plugin \
    --plugin=eosio::net_plugin \
    --http-server-address=127.0.0.1:8888 \
    --http-validate-host=false \
    --p2p-listen-endpoint=0.0.0.0:9876 \
    "${peer_args[@]}" \
    --read-mode=irreversible \
    --validation-mode=full \
    --wasm-runtime=eos-vm \
    --chain-state-db-size-mb="${XPR_CHAIN_STATE_DB_SIZE_MB:-32768}" \
    --sync-fetch-span="${XPR_SYNC_FETCH_SPAN:-2000}" \
    --max-clients=100 \
    >"$LOG_FILE" 2>&1 &
  pid=$!
  printf '%s\n' "$pid" >"$PID_FILE"
  sleep 2
  if ! pid_is_nodeos "$pid"; then
    tail -n 100 "$LOG_FILE" >&2 || true
    fail "nodeos exited during startup"
  fi
  echo "nodeos_pid=$pid"
  echo "blocks_dir=$BLOCKS_DIR"
  echo "log=$LOG_FILE"
}

show_status() {
  local pid=""
  [[ -s "$PID_FILE" ]] && pid="$(<"$PID_FILE")"
  if pid_is_nodeos "$pid"; then
    echo "nodeos=running pid=$pid"
  else
    echo "nodeos=stopped"
  fi
  if curl -fsS --max-time 3 -H 'content-type: application/json' \
    http://127.0.0.1:8888/v1/chain/get_info >"$SOURCE_ROOT/get-info.json"; then
    jq '{chain_id,head_block_num,last_irreversible_block_num,head_block_time}' \
      "$SOURCE_ROOT/get-info.json"
  else
    echo "rpc=not-ready"
  fi
  if [[ -e "$BLOCKS_DIR/blocks.log" ]]; then
    du -h "$BLOCKS_DIR/blocks.log" "$BLOCKS_DIR/blocks.index" 2>/dev/null || true
  fi
}

stop_nodeos() {
  [[ -s "$PID_FILE" ]] || fail "no nodeos PID is recorded"
  local pid
  pid="$(<"$PID_FILE")"
  if ! pid_is_nodeos "$pid"; then
    fail "recorded PID $pid is not this XPR nodeos"
  fi
  kill -TERM "$pid"
  for _ in {1..60}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "nodeos stopped"
      return
    fi
    sleep 1
  done
  fail "nodeos did not stop within 60 seconds"
}

usage() {
  cat <<EOF
Usage: scripts/acquire-xpr-mainnet-blocklog.sh [start|status|logs|stop]

Environment:
  XPR_NODEOS              Pinned Leap 5.0.3 nodeos executable.
  XPR_SOURCE_DIR          Durable source directory (default: /data/xpr-mainnet-source).
  XPR_CHAIN_STATE_DB_SIZE_MB  nodeos chain-state reservation (default: 32768).

The source block log is written to:
  $BLOCKS_DIR
EOF
}

case "$ACTION" in
  start) start_nodeos ;;
  status) show_status ;;
  logs) tail -n 200 -f "$LOG_FILE" ;;
  stop) stop_nodeos ;;
  help|-h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
