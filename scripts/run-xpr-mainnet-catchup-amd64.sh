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
  [[ -s "$NODE_ROOT/state/shared_memory.bin" ]] || \
    fail "missing provider chainbase state: $NODE_ROOT/state/shared_memory.bin"
  [[ -s "$NODE_ROOT/blocks/blocks.log" ]] || \
    fail "missing block log: $NODE_ROOT/blocks/blocks.log"
  [[ -s "$NODE_ROOT/blocks/blocks.index" ]] || \
    fail "missing block index: $NODE_ROOT/blocks/blocks.index"
  [[ -s "$NODE_ROOT/blocks/reversible/fork_db.dat" ]] || \
    fail "missing matching reversible fork database; restore blocks/reversible/fork_db.dat from the same blocks archive"
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
    --read-mode=irreversible \
    --validation-mode=light \
    --wasm-runtime=eos-vm \
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
