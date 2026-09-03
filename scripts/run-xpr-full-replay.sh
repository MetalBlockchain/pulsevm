#!/usr/bin/env bash
# Build and supervise a sequential, genesis-to-tip XPR Mainnet replay on Linux.
set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ACTION="${1:-status}"
readonly SOURCE_DIR="${XPR_REPLAY_SOURCE_DIR:-/data/xpr-mainnet-archive}"
readonly ARENA_DIR="${XPR_REPLAY_ARENA_DIR:-/data/xpr-arena-replay}"
readonly LOG_FILE="${XPR_REPLAY_LOG_FILE:-/data/xpr-mainnet-replay.log}"
readonly TARGET_DIR="${XPR_REPLAY_TARGET_DIR:-$REPO_ROOT/target/xpr-replay-native}"
readonly BINARY="$TARGET_DIR/release/examples/xpr_blocklog_replay"
readonly SERVICE="${XPR_REPLAY_SERVICE:-pulsevm-xpr-mainnet-replay}.service"
readonly CHECKPOINT_INTERVAL="${XPR_REPLAY_CHECKPOINT_INTERVAL:-1000000}"
readonly LAST_BLOCK="${XPR_REPLAY_LAST_BLOCK:-}"

fail() {
  echo "error: $*" >&2
  exit 1
}

require_linux() {
  [[ "$(uname -s)" == "Linux" ]] || fail "full XPR replay requires Linux"
  command -v systemd-run >/dev/null || fail "systemd-run is required"
}

validate_uint() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]] || fail "$2 must be a positive integer"
}

build_replay() {
  require_linux
  local rustflags="-C target-cpu=native"
  # Wasmer's coroutine dependency does not preserve SVE's reserved FFR register.
  # Keep all other Neoverse features while avoiding that unsafe codegen path.
  if [[ "$(uname -m)" == "aarch64" ]]; then
    rustflags+=" -C target-feature=-sve"
  fi

  echo "==> Building the host-native replay binary with ThinLTO"
  (
    cd "$REPO_ROOT"
    CARGO_TARGET_DIR="$TARGET_DIR" \
      CARGO_PROFILE_RELEASE_LTO=thin \
      CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
      RUSTFLAGS="$rustflags" \
      cargo build --release --locked -p pulsevm_core --example xpr_blocklog_replay
  )
  echo "binary=$BINARY"
}

start_replay() {
  require_linux
  validate_uint "$CHECKPOINT_INTERVAL" XPR_REPLAY_CHECKPOINT_INTERVAL
  [[ -z "$LAST_BLOCK" ]] || validate_uint "$LAST_BLOCK" XPR_REPLAY_LAST_BLOCK
  [[ -x "$BINARY" ]] || fail "replay binary is missing; run '$0 build' first"
  [[ -s "$SOURCE_DIR/blocks.log" ]] || fail "missing $SOURCE_DIR/blocks.log"
  [[ -s "$SOURCE_DIR/blocks.index" ]] || fail "missing $SOURCE_DIR/blocks.index"
  local index_size source_blocks
  index_size="$(stat -c %s "$SOURCE_DIR/blocks.index")"
  (( index_size % 8 == 0 )) || fail "source block index size is not divisible by 8"
  source_blocks="$((index_size / 8))"
  if [[ -n "$LAST_BLOCK" ]] && (( LAST_BLOCK > source_blocks )); then
    fail "requested block $LAST_BLOCK exceeds source corpus head $source_blocks"
  fi
  mkdir -p "$ARENA_DIR" "$(dirname "$LOG_FILE")"

  if systemctl --user is-active --quiet "$SERVICE"; then
    fail "$SERVICE is already running"
  fi
  systemctl --user reset-failed "$SERVICE" 2>/dev/null || true

  local command=(
    env "XPR_REPLAY_CHECKPOINT_INTERVAL=$CHECKPOINT_INTERVAL"
    "$BINARY" "$SOURCE_DIR" "$ARENA_DIR"
  )
  [[ -z "$LAST_BLOCK" ]] || command+=("$LAST_BLOCK")

  # Retry only abnormal process death. A normal non-zero exit is a parity error
  # and must remain stopped and visible instead of entering a restart loop.
  systemd-run --user \
    --unit="${SERVICE%.service}" \
    --property=Restart=on-abnormal \
    --property=RestartSec=5s \
    --property="StandardOutput=append:$LOG_FILE" \
    --property="StandardError=append:$LOG_FILE" \
    --working-directory="$REPO_ROOT" \
    "${command[@]}"
  echo "service=$SERVICE"
  echo "log=$LOG_FILE"
}

show_status() {
  require_linux
  systemctl --user status "$SERVICE" --no-pager --lines=5 || true
  if [[ -s "$SOURCE_DIR/blocks.index" ]]; then
    local index_size
    index_size="$(stat -c %s "$SOURCE_DIR/blocks.index")"
    if (( index_size % 8 == 0 )); then
      echo "source_blocks=$((index_size / 8))"
    else
      echo "source_index_bytes=$index_size (not divisible by 8)"
    fi
  fi
  if [[ -s "$LOG_FILE" ]]; then
    grep -E 'database revision:|accepted block|replay passed|replay failed|Error:' \
      "$LOG_FILE" | tail -n 5 || true
  fi
}

stop_replay() {
  require_linux
  systemctl --user stop "$SERVICE"
  echo "$SERVICE stopped; the next start resumes from the last durable Arena checkpoint"
}

usage() {
  cat <<EOF
Usage: scripts/run-xpr-full-replay.sh [build|start|status|logs|stop]

Environment:
  XPR_REPLAY_SOURCE_DIR          Leap blocks.log directory (default: /data/xpr-mainnet-archive)
  XPR_REPLAY_ARENA_DIR           Durable Arena state directory
  XPR_REPLAY_LOG_FILE            Replay log path
  XPR_REPLAY_TARGET_DIR          Native Cargo target directory
  XPR_REPLAY_SERVICE             systemd user service name without .service
  XPR_REPLAY_LAST_BLOCK          Optional pinned terminal block
  XPR_REPLAY_CHECKPOINT_INTERVAL Durable checkpoint interval (default: 1000000)
EOF
}

case "$ACTION" in
  build) build_replay ;;
  start) start_replay ;;
  status) show_status ;;
  logs) tail -n 200 -f "$LOG_FILE" ;;
  stop) stop_replay ;;
  help|-h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
