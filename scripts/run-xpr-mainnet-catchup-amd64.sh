#!/usr/bin/env bash
# Run the official AMD64 Leap binary against provider chainbase state on ARM.
set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ACTION="${1:-status}"
readonly IMAGE="${XPR_NODEOS_IMAGE:-pulsevm-leap:5.0.3-amd64}"
readonly CONTAINER="${XPR_NODEOS_CONTAINER:-xpr-mainnet-catchup-amd64}"
readonly PLATFORM="${XPR_NODEOS_PLATFORM:-linux/amd64}"
readonly NODE_ROOT="${XPR_CORPUS_NODE_ROOT:-/data/xpr-mainnet-current-node}"
readonly CONFIG_DIR="${XPR_CONFIG_DIR:-/data/xpr-mainnet-source/config}"
readonly HTTP_ENDPOINT="${XPR_LOCAL_HTTP_ENDPOINT:-127.0.0.1:8888}"
readonly P2P_ENDPOINT="${XPR_LOCAL_P2P_ENDPOINT:-127.0.0.1:9876}"
readonly READ_MODE="${XPR_NODEOS_READ_MODE:-irreversible}"
readonly VALIDATION_MODE="${XPR_NODEOS_VALIDATION_MODE:-light}"
readonly API_ACCEPT_TRANSACTIONS="${XPR_API_ACCEPT_TRANSACTIONS:-0}"
readonly P2P_ACCEPT_TRANSACTIONS="${XPR_P2P_ACCEPT_TRANSACTIONS:-$API_ACCEPT_TRANSACTIONS}"
readonly ALLOW_EMPTY_REVERSIBLE_DB="${XPR_ALLOW_EMPTY_REVERSIBLE_DB:-0}"
readonly WASM_RUNTIME="${XPR_WASM_RUNTIME:-eos-vm-jit}"
readonly EOS_VM_OC_ENABLE="${XPR_EOS_VM_OC_ENABLE:-all}"
readonly DOCKERFILE="$REPO_ROOT/tools/xpr-chainbase-export/localnet/Dockerfile.leap-amd64"

fail() {
  echo "error: $*" >&2
  exit 1
}

docker_command() {
  if docker info >/dev/null 2>&1; then
    printf '%s\n' docker
  elif sudo -n docker info >/dev/null 2>&1; then
    printf '%s\n' "sudo docker"
  else
    fail "Docker is unavailable; grant access to its socket or passwordless sudo docker"
  fi
}

run_docker() {
  local docker
  docker="$(docker_command)"
  # Intentional word splitting: docker_command returns either `docker` or
  # `sudo docker`, never user-controlled text.
  # shellcheck disable=SC2086
  $docker "$@"
}

require_corpus() {
  [[ "$READ_MODE" == head || "$READ_MODE" == irreversible || "$READ_MODE" == speculative ]] || \
    fail "XPR_NODEOS_READ_MODE must be head, irreversible, or speculative"
  [[ "$VALIDATION_MODE" == full || "$VALIDATION_MODE" == light ]] || \
    fail "XPR_NODEOS_VALIDATION_MODE must be full or light"
  [[ "$API_ACCEPT_TRANSACTIONS" == 0 || "$API_ACCEPT_TRANSACTIONS" == 1 ]] || \
    fail "XPR_API_ACCEPT_TRANSACTIONS must be 0 or 1"
  [[ "$P2P_ACCEPT_TRANSACTIONS" == 0 || "$P2P_ACCEPT_TRANSACTIONS" == 1 ]] || \
    fail "XPR_P2P_ACCEPT_TRANSACTIONS must be 0 or 1"
  [[ "$ALLOW_EMPTY_REVERSIBLE_DB" == 0 || "$ALLOW_EMPTY_REVERSIBLE_DB" == 1 ]] || \
    fail "XPR_ALLOW_EMPTY_REVERSIBLE_DB must be 0 or 1"
  if [[ "$API_ACCEPT_TRANSACTIONS" == 1 ]]; then
    [[ "$READ_MODE" == head ]] || \
      fail "API transaction submission requires XPR_NODEOS_READ_MODE=head"
    [[ "$P2P_ACCEPT_TRANSACTIONS" == 1 ]] || \
      fail "API transaction submission requires XPR_P2P_ACCEPT_TRANSACTIONS=1 to relay accepted transactions"
  fi
  [[ -s "$NODE_ROOT/state/shared_memory.bin" ]] || \
    fail "missing provider chainbase state: $NODE_ROOT/state/shared_memory.bin"
  [[ -s "$NODE_ROOT/blocks/blocks.log" ]] || \
    fail "missing block log: $NODE_ROOT/blocks/blocks.log"
  [[ -s "$NODE_ROOT/blocks/blocks.index" ]] || \
    fail "missing block index: $NODE_ROOT/blocks/blocks.index"
  if [[ ! -s "$NODE_ROOT/blocks/reversible/fork_db.dat" ]]; then
    [[ "$ALLOW_EMPTY_REVERSIBLE_DB" == 1 && "$READ_MODE" == head && \
      "$API_ACCEPT_TRANSACTIONS" == 1 ]] || \
      fail "missing matching reversible fork database; set XPR_ALLOW_EMPTY_REVERSIBLE_DB=1 only for a verified state/log pair that can resume from its irreversible head"
    echo "warning: starting from an empty reversible database; verify the state/log pair is at an irreversible boundary" >&2
  fi
  [[ -d "$CONFIG_DIR" ]] || fail "missing nodeos config directory: $CONFIG_DIR"
}

build_image() {
  [[ -f "$DOCKERFILE" ]] || fail "missing $DOCKERFILE"
  run_docker build \
    --platform "$PLATFORM" \
    --tag "$IMAGE" \
    --file "$DOCKERFILE" \
    "$REPO_ROOT"
  run_docker run --rm --platform "$PLATFORM" "$IMAGE" --full-version
}

start_nodeos() {
  require_corpus
  if run_docker inspect "$CONTAINER" >/dev/null 2>&1; then
    if [[ "$(run_docker inspect --format '{{.State.Running}}' "$CONTAINER")" == true ]]; then
      fail "$CONTAINER is already running"
    fi
    run_docker rm "$CONTAINER" >/dev/null
  fi

  local state_size state_size_mb
  state_size="$(stat -c %s "$NODE_ROOT/state/shared_memory.bin")"
  ((state_size % 1048576 == 0)) || fail "chainbase state size is not a whole number of MiB"
  state_size_mb="$((state_size / 1048576))"

  run_docker run --detach \
    --platform "$PLATFORM" \
    --name "$CONTAINER" \
    --restart unless-stopped \
    --network host \
    --mount "type=bind,src=$NODE_ROOT,dst=$NODE_ROOT" \
    --mount "type=bind,src=$CONFIG_DIR,dst=$CONFIG_DIR,readonly" \
    "$IMAGE" \
    "--data-dir=$NODE_ROOT" \
    "--config-dir=$CONFIG_DIR" \
    "--chain-state-db-size-mb=$state_size_mb" \
    "--read-mode=$READ_MODE" \
    "--validation-mode=$VALIDATION_MODE" \
    "--api-accept-transactions=$API_ACCEPT_TRANSACTIONS" \
    "--p2p-accept-transactions=$P2P_ACCEPT_TRANSACTIONS" \
    "--wasm-runtime=$WASM_RUNTIME" \
    "--eos-vm-oc-enable=$EOS_VM_OC_ENABLE" \
    "--http-server-address=$HTTP_ENDPOINT" \
    --http-validate-host=false \
    "--p2p-listen-endpoint=$P2P_ENDPOINT" \
    --sync-fetch-span=2000 \
    --plugin=eosio::chain_api_plugin \
    --p2p-peer-address=xpr-mainnet-p2p.bloxprod.io:9876 \
    --p2p-peer-address=p2p-protonmain.saltant.io:9876 \
    --p2p-peer-address=proton.protonuk.io:9876
  echo "container=$CONTAINER"
  echo "blocks=$NODE_ROOT/blocks"
  echo "read_mode=$READ_MODE api_accept_transactions=$API_ACCEPT_TRANSACTIONS p2p_accept_transactions=$P2P_ACCEPT_TRANSACTIONS"
}

show_status() {
  run_docker ps --all \
    --filter "name=^/${CONTAINER}$" \
    --format '{{.Names}} {{.Status}}'
  if [[ -s "$NODE_ROOT/blocks/blocks.index" ]]; then
    local index_size
    index_size="$(stat -c %s "$NODE_ROOT/blocks/blocks.index")"
    if ((index_size % 8 == 0)); then
      echo "corpus_blocks=$((index_size / 8))"
    else
      echo "corpus_index_bytes=$index_size (invalid: not divisible by 8)"
    fi
  fi
  curl -fsS --max-time 3 \
    -H 'content-type: application/json' \
    "http://$HTTP_ENDPOINT/v1/chain/get_info" 2>/dev/null | \
    jq '{head_block_num,last_irreversible_block_num,head_block_time}' || echo "rpc=not-ready"
}

stop_nodeos() {
  run_docker stop --time 60 "$CONTAINER"
}

usage() {
  cat <<EOF
Usage: scripts/run-xpr-mainnet-catchup-amd64.sh [build|start|status|logs|stop]

This runner is for provider state created by the official x86_64 Leap build.
On ARM hosts, install qemu-user-static and binfmt-support before `build`.

Environment:
  XPR_NODEOS_IMAGE       Docker image name
  XPR_NODEOS_CONTAINER   Persistent container name
  XPR_NODEOS_PLATFORM    Docker platform (default: linux/amd64)
  XPR_CORPUS_NODE_ROOT   Matching state/ and blocks/ directory
  XPR_CONFIG_DIR         nodeos config directory
  XPR_LOCAL_HTTP_ENDPOINT
  XPR_LOCAL_P2P_ENDPOINT
  XPR_NODEOS_READ_MODE        irreversible by default; set head to accept API transactions
  XPR_NODEOS_VALIDATION_MODE  full or light (default: light for the ARM replay host)
  XPR_API_ACCEPT_TRANSACTIONS 0 by default; set to 1 to enable chain API submission
  XPR_P2P_ACCEPT_TRANSACTIONS defaults to API setting; must be 1 to relay transactions
  XPR_ALLOW_EMPTY_REVERSIBLE_DB 1 only for a verified irreversible state/log pair
  XPR_WASM_RUNTIME            Leap WASM runtime (default: eos-vm-jit)
  XPR_EOS_VM_OC_ENABLE        OC enable setting (default: all)
EOF
}

case "$ACTION" in
  build) build_image ;;
  start) start_nodeos ;;
  status) show_status ;;
  logs) run_docker logs --follow --tail 200 "$CONTAINER" ;;
  stop) stop_nodeos ;;
  help|-h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
