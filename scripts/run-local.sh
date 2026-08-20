#!/usr/bin/env bash
#
# Spin up a local PulseVM cluster with metal-network-runner, so a real node
# writes a real block_log we can replay against the Rust database.
#
# Prerequisites you must supply:
#   * METALGO_EXEC_PATH  — a compiled `metalgo` binary whose rpcchainvm
#     protocol version matches this VM's PLUGIN_VERSION (currently 43; see
#     crates/pulsevm_core/src/chain/config/mod.rs). A mismatch fails the
#     plugin handshake.
#   * PULSEVM_MIGRATION_CHECKPOINT (optional) — an Arena checkpoint emitted by
#     `xpr_import_check`. When set, every VM node restores this state instead
#     of authoring normal Arena genesis state.
#   * go, protoc, and LLVM 22 (`LLVM_SYS_221_PREFIX`) for the plugin build.
#
# This script automates the deterministic setup (build + stage the plugin,
# install metal-network-runner, start the cluster from genesis.json). Pulling
# the block_log off a node and running the replay is the last step, documented
# at the bottom — it depends on the live cluster's node paths.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM_ID="rXcAFxZvio99epp6TzEwYfexCfPAbJuBTMsjUUoiT7PkVykNs"
BUILD_DIR="$REPO/build"
NETWORK_RUNNER="${METAL_NETWORK_RUNNER_PATH:-$REPO/../metal-network-runner/bin/metal-network-runner}"
MIGRATION_GENESIS=""

if [[ -z "${METALGO_EXEC_PATH:-}" || ! -x "${METALGO_EXEC_PATH:-}" ]]; then
  echo "error: set METALGO_EXEC_PATH to a metalgo binary (rpcchainvm protocol 43)." >&2
  echo "       releases: https://github.com/MetalBlockchain/metalgo/releases" >&2
  exit 1
fi

echo "==> Building the PulseVM plugin (release)"
( cd "$REPO" && cargo build --release -p pulsevm )

echo "==> Staging the plugin as $VM_ID"
mkdir -p "$BUILD_DIR"
cp "$REPO/target/release/pulsevm" "$BUILD_DIR/$VM_ID"
chmod +x "$BUILD_DIR/$VM_ID"

echo "==> Locating metal-network-runner"
if [[ ! -x "$NETWORK_RUNNER" ]]; then
  if command -v metal-network-runner >/dev/null 2>&1; then
    NETWORK_RUNNER="$(command -v metal-network-runner)"
  else
    go install github.com/MetalBlockchain/metal-network-runner@latest
    NETWORK_RUNNER="$(go env GOPATH)/bin/metal-network-runner"
  fi
fi

BLOCKCHAIN_SPECS="[{\"vm_name\": \"pulsevm\", \"genesis\": \"$REPO/genesis.json\"}]"
if [[ -n "${PULSEVM_MIGRATION_CHECKPOINT:-}" ]]; then
  if [[ ! -f "$PULSEVM_MIGRATION_CHECKPOINT" ]]; then
    echo "error: PULSEVM_MIGRATION_CHECKPOINT does not exist: $PULSEVM_MIGRATION_CHECKPOINT" >&2
    exit 1
  fi
  MIGRATION_MANIFEST="${PULSEVM_MIGRATION_MANIFEST:-${PULSEVM_MIGRATION_CHECKPOINT}.manifest.json}"
  if [[ ! -f "$MIGRATION_MANIFEST" ]]; then
    echo "error: migration manifest does not exist: $MIGRATION_MANIFEST" >&2
    exit 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required to pass a migration checkpoint to the runner." >&2
    exit 1
  fi
  CHECKPOINT_SHA256="$(jq -er '.checkpoint_sha256 | select(type == "string" and test("^[[:xdigit:]]{64}$"))' "$MIGRATION_MANIFEST")"
  MIGRATION_GENESIS="$(mktemp "${TMPDIR:-/tmp}/pulsevm-xpr-migration-genesis.XXXXXX")"
  jq --arg checkpoint_sha256 "$CHECKPOINT_SHA256" \
    '. + {migration_checkpoint_sha256: $checkpoint_sha256}' \
    "$REPO/genesis.json" > "$MIGRATION_GENESIS"
  # This development key corresponds to genesis.json's initial_key. Override it
  # for a real producer deployment; it is part of the node-local VM config.
  PRODUCER_KEY="${PULSEVM_PRODUCER_KEY:-PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez}"
  CHAIN_CONFIG="$(jq -cn \
    --arg checkpoint "$PULSEVM_MIGRATION_CHECKPOINT" \
    --arg manifest "$MIGRATION_MANIFEST" \
    --arg producer_key "$PRODUCER_KEY" \
    '{producer_name: "pulse", producer_key: $producer_key, migration_checkpoint: $checkpoint, migration_manifest: $manifest}')"
  BLOCKCHAIN_SPECS="$(jq -cn \
    --arg genesis "$MIGRATION_GENESIS" \
    --arg chain_config "$CHAIN_CONFIG" \
    '[{vm_name: "pulsevm", genesis: $genesis, chain_config: $chain_config, blockchain_alias: "pulse-xpr-migration"}]')"
  echo "==> Configured all VM nodes to restore $PULSEVM_MIGRATION_CHECKPOINT"
  echo "==> Generated migration-specific genesis committed to $CHECKPOINT_SHA256"
fi

echo "==> Starting metal-network-runner server (background)"
"$NETWORK_RUNNER" server --log-level info --port=":8080" --grpc-gateway-port=":8081" &
ANR_PID=$!
trap 'rm -f -- "$MIGRATION_GENESIS"; kill $ANR_PID 2>/dev/null || true' EXIT
sleep 3

echo "==> Launching a 5-node cluster running PulseVM"
"$NETWORK_RUNNER" control start --log-level info \
  --endpoint="0.0.0.0:8080" \
  --number-of-nodes=5 \
  --metalgo-path "$METALGO_EXEC_PATH" \
  --plugin-dir "$BUILD_DIR" \
  --blockchain-specs "$BLOCKCHAIN_SPECS"

echo
echo "Cluster starting. Once 'control status' reports the blockchain healthy:"
echo
echo "  1) Note a node's data dir (metal-network-runner control status), then find"
echo "     the PulseVM block_log it writes:"
echo "       find <node-data-dir> -name 'block_log.log' -print"
echo
echo "  2) Get the chain_id from the node's getInfo (pulsevm.getInfo over its RPC)."
echo
echo "  3) Submit a few transactions with the 'pulse' CLI so the node produces"
echo "     non-empty blocks (newaccount / setcode / ...), then replay + diff:"
echo
echo "       PULSEVM_REPLAY_BLOCK_LOG_DIR=<dir containing block_log.log> \\"
echo "       PULSEVM_REPLAY_GENESIS=$REPO/genesis.json \\"
echo "       PULSEVM_REPLAY_CHAIN_ID=<hex chain id from getInfo> \\"
echo "       cargo test -p pulsevm_core \\"
echo "         replay_local_block_log -- --ignored --nocapture"
echo
echo "That replays the real block_log into a fresh node and checks the arena"
echo "state root after every block."
wait $ANR_PID
