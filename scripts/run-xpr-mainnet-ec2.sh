#!/usr/bin/env bash
# Prepare a validated XPR Mainnet Arena checkpoint and keep a five-node
# PulseVM migration network running on one Linux/EC2 host.
set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly RUN_ROOT_LOCATOR="$REPO_ROOT/build/xpr-mainnet-ec2-run-root"

absolute_from_repo() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$REPO_ROOT" "$1" ;;
  esac
}

run_root_input="${PULSEVM_EC2_RUN_DIR:-}"
if [[ -z "$run_root_input" && -s "$RUN_ROOT_LOCATOR" ]]; then
  run_root_input="$(<"$RUN_ROOT_LOCATOR")"
fi
readonly ACTION="${1:-start}"
readonly RUN_ROOT="$(absolute_from_repo "${run_root_input:-build/xpr-mainnet-ec2}")"
readonly EXPORT_DIR="$(absolute_from_repo "${XPR_EXPORT_DIR:-$RUN_ROOT/export}")"
readonly ARENA_DIR="$(absolute_from_repo "${XPR_ARENA_DIR:-$RUN_ROOT/arena}")"
readonly CANONICAL_CHECKPOINT="$(absolute_from_repo "${PULSEVM_MIGRATION_CHECKPOINT:-$RUN_ROOT/xpr-mainnet.snapshot}")"
readonly PID_FILE="$RUN_ROOT/cluster.pid"
readonly CURRENT_SESSION_FILE="$RUN_ROOT/current-session"
readonly VALIDATION_MARKER="$RUN_ROOT/mainnet-validation-passed"
readonly DEFAULT_TEST_KEY="PVT_K1_2pjSqJxTbRHq8h8aHHTux81Ypscb36Q2syB8UJbZcUmxbfZdnT"

cd "$REPO_ROOT"

usage() {
  cat <<'EOF'
Usage: scripts/run-xpr-mainnet-ec2.sh [prepare|start|status|logs|stop]

Fast path, when the canonical migration checkpoint already exists:
  METALGO_EXEC_PATH=../metalgo/build/metalgo \
  PULSEVM_MIGRATION_CHECKPOINT=/data/xpr-mainnet.snapshot \
    scripts/run-xpr-mainnet-ec2.sh start

Full snapshot-to-five-node path:
  XPR_SNAPSHOT=/data/xpr/snapshot.bin \
  XPR_NODEOS=/data/XPRNetwork-core/build/programs/nodeos/nodeos \
  XPR_CORE=/data/XPRNetwork-core \
  METALGO_EXEC_PATH=../metalgo/build/metalgo \
  PULSEVM_EC2_RUN_DIR=/data/pulsevm-xpr \
    scripts/run-xpr-mainnet-ec2.sh start

Commands:
  prepare  Export, import, validate, and derive the disposable test checkpoint.
  start    Run prepare when necessary, then launch five nodes in the background.
  status   Report the supervisor and last five-node convergence result.
  logs     Follow the current session log.
  stop     Stop the runner supervisor and its five nodes.

Environment:
  PULSEVM_MIGRATION_CHECKPOINT  Reuse an existing canonical checkpoint. Its
                                .manifest.json file must be beside it.
  PULSEVM_EC2_RUN_DIR           Durable artifacts/session root (default: build/...).
  METALGO_EXEC_PATH             Matching MetalGo binary (required).
  METAL_NETWORK_RUNNER_PATH     Runner binary (default: ../metal-network-runner/bin/...).
  PULSEVM_TEST_PRIVATE_KEY      Disposable K1 key used only by this test network.
  PULSEVM_PRODUCER_NAME         Imported producer account (default: pulse).
  PULSEVM_PRODUCER_KEY          Real producer key, required only with the option below.
  XPR_SOURCE_BLOCK_JSON         Optional get_block JSON for the snapshot boundary.
  XPR_SOURCE_API_URL            Archive API used when that JSON is absent
                                (default: https://proton.eosusa.io).
  PULSEVM_PRESERVE_IMPORTED_AUTHORITY=true
                                Boot the canonical authority unchanged. The supplied
                                producer key must then be the real matching key.

For a raw snapshot, XPR_NODEOS must already be rebuilt from the pinned XPR_CORE
revision with the deferred-sidecar plugin. This command deliberately boots from
the snapshot boundary; it does not replay XPR's complete historical block corpus.
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command '$1'"
}

remember_run_root() {
  mkdir -p "$(dirname "$RUN_ROOT_LOCATOR")"
  printf '%s\n' "$RUN_ROOT" >"$RUN_ROOT_LOCATOR"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

validation_is_current() {
  [[ -s "$VALIDATION_MARKER" ]] || return 1
  [[ "$(<"$VALIDATION_MARKER")" == "$(sha256_file "$CANONICAL_CHECKPOINT")" ]]
}

validate_canonical_checkpoint() {
  local snapshot="${1:-}"
  local validation_args=(
    --export-dir "$EXPORT_DIR"
    --checkpoint "$CANONICAL_CHECKPOINT"
    --arena-dir "$ARENA_DIR"
  )
  if [[ -n "$snapshot" ]]; then
    validation_args+=(--snapshot "$snapshot")
  fi
  LLVM_SYS_221_PREFIX="${LLVM_SYS_221_PREFIX:-/usr/lib/llvm-22}" \
    "$REPO_ROOT/tools/xpr-chainbase-export/validate-mainnet-export.sh" \
      "${validation_args[@]}"
  sha256_file "$CANONICAL_CHECKPOINT" >"$VALIDATION_MARKER"
}

find_metalgo() {
  local candidate
  if [[ -n "${METALGO_EXEC_PATH:-}" ]]; then
    printf '%s\n' "$METALGO_EXEC_PATH"
    return
  fi
  for candidate in \
    "$REPO_ROOT/../metalgo/build/metalgo" \
    "$REPO_ROOT/../metalgo/metalgo"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  fail "set METALGO_EXEC_PATH to the matching MetalGo binary"
}

find_runner() {
  local candidate
  if [[ -n "${METAL_NETWORK_RUNNER_PATH:-}" ]]; then
    printf '%s\n' "$METAL_NETWORK_RUNNER_PATH"
    return
  fi
  candidate="$REPO_ROOT/../metal-network-runner/bin/metal-network-runner"
  if [[ -x "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return
  fi
  if command -v metal-network-runner >/dev/null 2>&1; then
    command -v metal-network-runner
    return
  fi
  fail "set METAL_NETWORK_RUNNER_PATH or place the runner at ../metal-network-runner/bin/metal-network-runner"
}

check_build_prerequisites() {
  [[ "$(uname -s)" == "Linux" ]] || fail "this entry point is intended for Linux/EC2"
  require_command cargo
  require_command curl
  require_command jq
  require_command protoc
  require_command rg
  local llvm_prefix="${LLVM_SYS_221_PREFIX:-/usr/lib/llvm-22}"
  [[ -d "$llvm_prefix" ]] || fail "LLVM 22 not found at $llvm_prefix; set LLVM_SYS_221_PREFIX"
}

prepare_canonical_checkpoint() {
  if [[ -s "$CANONICAL_CHECKPOINT" && -s "$CANONICAL_CHECKPOINT.manifest.json" ]]; then
    if [[ -n "${PULSEVM_MIGRATION_CHECKPOINT:-}" ]]; then
      echo "==> Reusing operator-supplied checkpoint $CANONICAL_CHECKPOINT"
      return
    fi
    if validation_is_current; then
      echo "==> Reusing validated canonical checkpoint $CANONICAL_CHECKPOINT"
      return
    fi
    [[ -d "$ARENA_DIR" && -s "$EXPORT_DIR/manifest.env" ]] || \
      fail "script-produced checkpoint has no checksum-bound validation marker"
    echo "==> Retrying validation of the existing canonical checkpoint"
    validate_canonical_checkpoint "${XPR_SNAPSHOT:-}"
    echo "==> Reusing canonical checkpoint $CANONICAL_CHECKPOINT"
    return
  fi

  local snapshot="${XPR_SNAPSHOT:-}"
  local nodeos="${XPR_NODEOS:-}"
  local xpr_core="${XPR_CORE:-}"
  [[ -s "$snapshot" ]] || fail "set XPR_SNAPSHOT, or provide PULSEVM_MIGRATION_CHECKPOINT"
  [[ -x "$nodeos" ]] || fail "set XPR_NODEOS to the rebuilt sidecar-enabled nodeos"
  [[ -d "$xpr_core/.git" ]] || fail "set XPR_CORE to the pinned XPR source checkout"
  [[ ! -e "$CANONICAL_CHECKPOINT" ]] || fail "checkpoint exists without its manifest: $CANONICAL_CHECKPOINT"

  mkdir -p "$RUN_ROOT"
  echo "==> Running XPR source, sidecar, snapshot, and disk preflight"
  "$REPO_ROOT/tools/xpr-chainbase-export/preflight.sh" \
    --nodeos "$nodeos" \
    --snapshot "$snapshot" \
    --xpr-core "$xpr_core" \
    --require-sidecar-plugin \
    --minimum-free-gib "${XPR_MINIMUM_FREE_GIB:-250}"

  if [[ ! -s "$RUN_ROOT/host-function-audit.json" ]]; then
    echo "==> Auditing the exact XPR host-function registry"
    "$REPO_ROOT/tools/xpr-chainbase-export/host-function-audit.sh" \
      --xpr-core "$xpr_core" --strict \
      --report "$RUN_ROOT/host-function-audit.json"
  fi

  if [[ ! -s "$EXPORT_DIR/manifest.env" ]]; then
    [[ ! -e "$EXPORT_DIR" ]] || fail "partial export exists at $EXPORT_DIR; inspect it and choose a new XPR_EXPORT_DIR"
    echo "==> Exporting logical chainbase state and the deferred sidecar"
    local export_args=(
      --nodeos "$nodeos"
      --snapshot "$snapshot"
      --xpr-core "$xpr_core"
      --work-dir "$EXPORT_DIR"
      --deferred-sidecar "$EXPORT_DIR/deferred-transactions.json"
      --timeout-seconds "${XPR_EXPORT_TIMEOUT_SECONDS:-1800}"
      --chain-state-db-size-mb "${XPR_CHAIN_STATE_DB_SIZE_MB:-4096}"
      --resource-monitor-space-threshold "${XPR_RESOURCE_MONITOR_SPACE_THRESHOLD:-0}"
    )
    "$REPO_ROOT/tools/xpr-chainbase-export/export.sh" "${export_args[@]}"
  else
    echo "==> Reusing XPR export $EXPORT_DIR"
  fi

  [[ -s "$EXPORT_DIR/state-history/chain_state_history.log" ]] || fail "export has no chain-state history log"
  [[ -s "$EXPORT_DIR/deferred-transactions.json" ]] || fail "export has no deferred sidecar"
  [[ ! -e "$ARENA_DIR" ]] || fail "Arena import directory already exists without a checkpoint: $ARENA_DIR"
  mkdir -p "$(dirname "$CANONICAL_CHECKPOINT")"

  echo "==> Importing all logical XPR state into Arena"
  LLVM_SYS_221_PREFIX="${LLVM_SYS_221_PREFIX:-/usr/lib/llvm-22}" \
    cargo run --release --locked -p pulsevm_database --example xpr_import_check -- \
      "$EXPORT_DIR/state-history/chain_state_history.log" \
      "$ARENA_DIR" \
      "$CANONICAL_CHECKPOINT" \
      "$EXPORT_DIR/deferred-transactions.json"

  echo "==> Running the Mainnet manifest, 19-table, code-object, and sidecar gates"
  validate_canonical_checkpoint "$snapshot"
}

prepare_boot_checkpoint() {
  prepare_canonical_checkpoint
  if [[ "${PULSEVM_PRESERVE_IMPORTED_AUTHORITY:-false}" == "true" ]]; then
    [[ -n "${PULSEVM_PRODUCER_KEY:-}" ]] || fail "set PULSEVM_PRODUCER_KEY when preserving the imported authority"
    BOOT_CHECKPOINT="$CANONICAL_CHECKPOINT"
    BOOT_PRODUCER_KEY="$PULSEVM_PRODUCER_KEY"
    return
  fi

  local test_key="${PULSEVM_TEST_PRIVATE_KEY:-$DEFAULT_TEST_KEY}"
  local producer_name="${PULSEVM_PRODUCER_NAME:-pulse}"
  local source_hash key_hash
  source_hash="$(sha256_file "$CANONICAL_CHECKPOINT")"
  key_hash="$(printf '%s' "$test_key" | sha256sum | awk '{print $1}')"
  BOOT_CHECKPOINT="$RUN_ROOT/test-authority-${source_hash:0:12}-${key_hash:0:12}.snapshot"
  BOOT_PRODUCER_KEY="$test_key"
  if [[ ! -s "$BOOT_CHECKPOINT" || ! -s "$BOOT_CHECKPOINT.manifest.json" ]]; then
    echo "==> Deriving a disposable $producer_name authority for the EC2 test network"
    LLVM_SYS_221_PREFIX="${LLVM_SYS_221_PREFIX:-/usr/lib/llvm-22}" \
      cargo run --release --locked -p pulsevm_database --example xpr_test_authority -- \
        "$CANONICAL_CHECKPOINT" \
        "$CANONICAL_CHECKPOINT.manifest.json" \
        "$BOOT_CHECKPOINT" \
        "$test_key" \
        "$producer_name"
  else
    echo "==> Reusing disposable-authority checkpoint $BOOT_CHECKPOINT"
  fi
}

prepare_boot_manifest() {
  local input_manifest="$BOOT_CHECKPOINT.manifest.json"
  local checkpoint_hash source_id source_json temporary_json=""
  checkpoint_hash="$(jq -er '.checkpoint_sha256' "$input_manifest")"
  source_id="$(jq -er '.source_block_id' "$input_manifest")"
  BOOT_MANIFEST="$RUN_ROOT/boot-${checkpoint_hash:0:12}-${source_id:0:12}.manifest.json"
  if [[ -s "$BOOT_MANIFEST" ]] &&
     jq -e --arg checkpoint_hash "$checkpoint_hash" --arg source_id "$source_id" \
       '.checkpoint_sha256 == $checkpoint_hash and .source_block_id == $source_id and (.source_block | type == "string" and length > 0)' \
       "$BOOT_MANIFEST" >/dev/null; then
    echo "==> Reusing source-anchored migration manifest $BOOT_MANIFEST"
    return
  fi

  source_json="${XPR_SOURCE_BLOCK_JSON:-}"
  if [[ -z "$source_json" ]]; then
    temporary_json="$(mktemp "${TMPDIR:-/tmp}/xpr-source-block.XXXXXX.json")"
    source_json="$temporary_json"
    local source_api="${XPR_SOURCE_API_URL:-https://proton.eosusa.io}"
    echo "==> Fetching checkpoint boundary block $source_id from $source_api"
    curl --fail --silent --show-error \
      --request POST \
      --header 'Content-Type: application/json' \
      --data "$(jq -cn --arg source_id "$source_id" '{block_num_or_id: $source_id}')" \
      --output "$source_json" \
      "$source_api/v1/chain/get_block"
  fi
  [[ -s "$source_json" ]] || fail "source block JSON is empty: $source_json"

  echo "==> Binding the id-exact source block to the migration manifest"
  LLVM_SYS_221_PREFIX="${LLVM_SYS_221_PREFIX:-/usr/lib/llvm-22}" \
    cargo run --release --locked -p pulsevm_core --example xpr_attach_source_block -- \
      "$input_manifest" \
      "$source_json" \
      "$BOOT_MANIFEST"
  if [[ -n "$temporary_json" ]]; then
    rm -f -- "$temporary_json"
  fi
}

current_session() {
  [[ -s "$CURRENT_SESSION_FILE" ]] || fail "no EC2 session has been started"
  local session
  session="$(<"$CURRENT_SESSION_FILE")"
  [[ "$session" == "$RUN_ROOT"/sessions/* ]] || fail "invalid current-session path"
  printf '%s\n' "$session"
}

pid_is_running() {
  local pid="${1:-}"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$pid" 2>/dev/null
}

pid_is_cluster_supervisor() {
  local pid="${1:-}"
  pid_is_running "$pid" || return 1
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  tr '\0' ' ' <"/proc/$pid/cmdline" | grep -F -- "$REPO_ROOT/scripts/run-local.sh" >/dev/null
}

start_cluster() {
  check_build_prerequisites
  local metalgo runner
  metalgo="$(find_metalgo)"
  runner="$(find_runner)"
  [[ -x "$metalgo" ]] || fail "MetalGo is not executable: $metalgo"
  [[ -x "$runner" ]] || fail "metal-network-runner is not executable: $runner"

  if [[ -s "$PID_FILE" ]] && pid_is_running "$(<"$PID_FILE")"; then
    fail "a cluster is already running with PID $(<"$PID_FILE")"
  fi

  mkdir -p "$RUN_ROOT/sessions"
  remember_run_root
  prepare_boot_checkpoint
  prepare_boot_manifest

  local session report log pid timeout deadline
  session="$RUN_ROOT/sessions/$(date -u +%Y%m%dT%H%M%SZ)-$$"
  mkdir -p "$session/nodes"
  report="$session/five-node-replay.json"
  log="$session/cluster.log"
  printf '%s\n' "$session" >"$CURRENT_SESSION_FILE"

  timeout="${PULSEVM_EC2_START_TIMEOUT_SECONDS:-3600}"
  [[ "$timeout" =~ ^[1-9][0-9]*$ ]] || fail "PULSEVM_EC2_START_TIMEOUT_SECONDS must be positive"

  echo "==> Starting five nodes in the background"
  nohup env \
    LLVM_SYS_221_PREFIX="${LLVM_SYS_221_PREFIX:-/usr/lib/llvm-22}" \
    METALGO_EXEC_PATH="$metalgo" \
    METAL_NETWORK_RUNNER_PATH="$runner" \
    METAL_NETWORK_RUNNER_PORT="127.0.0.1:8080" \
    METAL_NETWORK_RUNNER_GATEWAY_PORT="127.0.0.1:8081" \
    METAL_NETWORK_RUNNER_ENDPOINT="127.0.0.1:8080" \
    METAL_NETWORK_RUNNER_ROOT_DATA_DIR="$session/nodes" \
    PULSEVM_MIGRATION_CHECKPOINT="$BOOT_CHECKPOINT" \
    PULSEVM_MIGRATION_MANIFEST="$BOOT_MANIFEST" \
    PULSEVM_PRODUCER_NAME="${PULSEVM_PRODUCER_NAME:-pulse}" \
    PULSEVM_PRODUCER_KEY="$BOOT_PRODUCER_KEY" \
    PULSEVM_FIVE_NODE_REPORT="$report" \
    "$REPO_ROOT/scripts/run-local.sh" >"$log" 2>&1 &
  pid=$!
  printf '%s\n' "$pid" >"$PID_FILE"

  deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    if [[ -s "$report" ]] && jq -e '.status == "passed" and .node_count == 5' "$report" >/dev/null; then
      echo "==> Five-node XPR migration network passed"
      jq '{status,node_count,chain_id,head_block_num,head_block_id}' "$report"
      echo "session=$session"
      echo "logs:   scripts/run-xpr-mainnet-ec2.sh logs"
      echo "stop:   scripts/run-xpr-mainnet-ec2.sh stop"
      return
    fi
    if ! pid_is_running "$pid"; then
      tail -n 100 "$log" >&2 || true
      fail "cluster exited before passing the five-node gate; log: $log"
    fi
    sleep 2
  done
  fail "cluster is still starting after ${timeout}s; inspect $log"
}

show_status() {
  local session pid report
  session="$(current_session)"
  pid=""
  [[ -s "$PID_FILE" ]] && pid="$(<"$PID_FILE")"
  report="$session/five-node-replay.json"
  if pid_is_cluster_supervisor "$pid"; then
    echo "supervisor=running pid=$pid"
  else
    echo "supervisor=stopped"
  fi
  echo "session=$session"
  if [[ -s "$report" ]]; then
    jq '{status,node_count,chain_id,head_block_num,head_block_id}' "$report"
  else
    echo "five_node_gate=pending"
  fi
}

follow_logs() {
  local session
  session="$(current_session)"
  touch "$session/cluster.log"
  tail -n 200 -f "$session/cluster.log"
}

stop_cluster() {
  [[ -s "$PID_FILE" ]] || fail "no cluster PID is recorded"
  local pid
  pid="$(<"$PID_FILE")"
  if ! pid_is_cluster_supervisor "$pid"; then
    echo "cluster is stopped; refusing to signal unrelated or stale PID $pid"
    return
  fi
  echo "==> Stopping five-node supervisor PID $pid"
  kill -TERM "$pid"
  for _ in {1..30}; do
    pid_is_running "$pid" || { echo "cluster stopped"; return; }
    sleep 1
  done
  fail "supervisor did not stop within 30 seconds; inspect the current session log"
}

if (($# > 1)); then
  usage >&2
  exit 2
fi

case "$ACTION" in
  prepare)
    check_build_prerequisites
    mkdir -p "$RUN_ROOT"
    remember_run_root
    prepare_boot_checkpoint
    prepare_boot_manifest
    echo "prepared boot checkpoint: $BOOT_CHECKPOINT"
    echo "prepared boot manifest:   $BOOT_MANIFEST"
    ;;
  start) start_cluster ;;
  status) show_status ;;
  logs) follow_logs ;;
  stop) stop_cluster ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
