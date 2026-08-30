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
#   * PULSEVM_GENESIS_PATH (optional) — genesis JSON to use. Set this to
#     tools/xpr-chainbase-export/xpr-mainnet-genesis.json for XPR Mainnet.
#   * go, protoc, and LLVM 22 (`LLVM_SYS_221_PREFIX`) for the plugin build.
#
# This script automates the deterministic setup (build + stage the plugin,
# install metal-network-runner, start the cluster from genesis.json), then runs
# the five-node RPC convergence/replay gate. Historical XPR replay remains a
# separate corpus-driven test because a local network does not contain XPR's
# historical block stream.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM_ID="rXcAFxZvio99epp6TzEwYfexCfPAbJuBTMsjUUoiT7PkVykNs"
BUILD_DIR="$REPO/build"
PLUGIN_DIR="${PULSEVM_PLUGIN_DIR:-$BUILD_DIR/plugins}"
NETWORK_RUNNER="${METAL_NETWORK_RUNNER_PATH:-$REPO/../metal-network-runner/bin/metal-network-runner}"
RUNNER_PORT="${METAL_NETWORK_RUNNER_PORT:-:8080}"
RUNNER_GATEWAY_PORT="${METAL_NETWORK_RUNNER_GATEWAY_PORT:-:8081}"
RUNNER_ENDPOINT="${METAL_NETWORK_RUNNER_ENDPOINT:-0.0.0.0$RUNNER_PORT}"
RUNNER_ROOT_DATA_DIR="${METAL_NETWORK_RUNNER_ROOT_DATA_DIR:-}"
RUNNER_REASSIGN_PORTS_IF_USED="${METAL_NETWORK_RUNNER_REASSIGN_PORTS_IF_USED:-false}"
MIGRATION_GENESIS=""
RUNNER_START_ARGS=()
GENESIS_PATH="${PULSEVM_GENESIS_PATH:-$REPO/genesis.json}"

if [[ -n "$RUNNER_ROOT_DATA_DIR" ]]; then
  RUNNER_START_ARGS+=(--root-data-dir "$RUNNER_ROOT_DATA_DIR")
fi
if [[ "$RUNNER_REASSIGN_PORTS_IF_USED" == "true" ]]; then
  RUNNER_START_ARGS+=(--reassign-ports-if-used)
fi

if [[ -z "${METALGO_EXEC_PATH:-}" || ! -x "${METALGO_EXEC_PATH:-}" ]]; then
  echo "error: set METALGO_EXEC_PATH to a metalgo binary (rpcchainvm protocol 43)." >&2
  echo "       releases: https://github.com/MetalBlockchain/metalgo/releases" >&2
  exit 1
fi

echo "==> Building the PulseVM plugin (release)"
( cd "$REPO" && cargo build --release -p pulsevm )

echo "==> Staging the plugin as $VM_ID"
mkdir -p "$PLUGIN_DIR"
cp "$REPO/target/release/pulsevm" "$PLUGIN_DIR/$VM_ID"
chmod +x "$PLUGIN_DIR/$VM_ID"

echo "==> Locating metal-network-runner"
if [[ ! -x "$NETWORK_RUNNER" ]]; then
  if command -v metal-network-runner >/dev/null 2>&1; then
    NETWORK_RUNNER="$(command -v metal-network-runner)"
  else
    go install github.com/MetalBlockchain/metal-network-runner@latest
    NETWORK_RUNNER="$(go env GOPATH)/bin/metal-network-runner"
  fi
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required to construct the runner chain configuration." >&2
  exit 1
fi
PRODUCER_NAME="${PULSEVM_PRODUCER_NAME:-pulse}"
PRODUCER_KEY="${PULSEVM_PRODUCER_KEY:-PVT_K1_2pjSqJxTbRHq8h8aHHTux81Ypscb36Q2syB8UJbZcUmxbfZdnT}"
SYSTEM_ACCOUNT="${PULSEVM_SYSTEM_ACCOUNT:-pulse}"
NATIVE_SYSTEM_CONTRACT="${PULSEVM_NATIVE_SYSTEM_CONTRACT:-true}"
if [[ ! -f "$GENESIS_PATH" ]]; then
  echo "error: genesis does not exist: $GENESIS_PATH" >&2
  exit 1
fi
case "$NATIVE_SYSTEM_CONTRACT" in
  true|false) ;;
  *)
    echo "error: PULSEVM_NATIVE_SYSTEM_CONTRACT must be true or false" >&2
    exit 1
    ;;
esac
# Always pass a node config. Without this field, metal-network-runner sends an
# empty config to the VM on clean (non-migration) starts, which fails before
# controller initialization with an opaque JSON EOF error.
CHAIN_CONFIG="$(jq -cn \
  --arg system_account "$SYSTEM_ACCOUNT" \
  --argjson native_system_contract "$NATIVE_SYSTEM_CONTRACT" \
  --arg producer_name "$PRODUCER_NAME" \
  --arg producer_key "$PRODUCER_KEY" \
  '{system_account: $system_account, native_system_contract: $native_system_contract, producer_name: $producer_name, producer_key: $producer_key}')"
BLOCKCHAIN_SPECS="$(jq -cn \
  --arg genesis "$GENESIS_PATH" \
  --arg chain_config "$CHAIN_CONFIG" \
  '[{vm_name: "pulsevm", genesis: $genesis, chain_config: $chain_config}]')"
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
  CHECKPOINT_SHA256="$(jq -er '.checkpoint_sha256 | select(type == "string" and test("^[[:xdigit:]]{64}$"))' "$MIGRATION_MANIFEST")"
  MIGRATION_GENESIS="$(mktemp "${TMPDIR:-/tmp}/pulsevm-xpr-migration-genesis.XXXXXX")"
  jq --arg checkpoint_sha256 "$CHECKPOINT_SHA256" \
    '. + {migration_checkpoint_sha256: $checkpoint_sha256}' \
    "$GENESIS_PATH" > "$MIGRATION_GENESIS"
  # This development key corresponds to genesis.json's initial_key. Override it
  # for a real producer deployment; it is part of the node-local VM config.
  CHAIN_CONFIG="$(jq -cn \
    --arg checkpoint "$PULSEVM_MIGRATION_CHECKPOINT" \
    --arg manifest "$MIGRATION_MANIFEST" \
    --arg producer_key "$PRODUCER_KEY" \
    --arg producer_name "$PRODUCER_NAME" \
    --arg system_account "$SYSTEM_ACCOUNT" \
    --argjson native_system_contract "$NATIVE_SYSTEM_CONTRACT" \
    '{system_account: $system_account, native_system_contract: $native_system_contract, producer_name: $producer_name, producer_key: $producer_key, migration_checkpoint: $checkpoint, migration_manifest: $manifest}')"
  BLOCKCHAIN_SPECS="$(jq -cn \
    --arg genesis "$MIGRATION_GENESIS" \
    --arg chain_config "$CHAIN_CONFIG" \
    '[{vm_name: "pulsevm", genesis: $genesis, chain_config: $chain_config, blockchain_alias: "pulse-xpr-migration"}]')"
  echo "==> Configured all VM nodes to restore $PULSEVM_MIGRATION_CHECKPOINT"
  echo "==> Generated migration-specific genesis committed to $CHECKPOINT_SHA256"
fi

echo "==> Starting metal-network-runner server (background)"
"$NETWORK_RUNNER" server --log-level info --port="$RUNNER_PORT" --grpc-gateway-port="$RUNNER_GATEWAY_PORT" &
ANR_PID=$!
trap 'rm -f -- "$MIGRATION_GENESIS"; kill $ANR_PID 2>/dev/null || true' EXIT
sleep 3

echo "==> Launching a 5-node cluster running PulseVM"
"$NETWORK_RUNNER" control start --log-level info \
  --endpoint="$RUNNER_ENDPOINT" \
  --number-of-nodes=5 \
  --metalgo-path "$METALGO_EXEC_PATH" \
  --plugin-dir "$PLUGIN_DIR" \
  "${RUNNER_START_ARGS[@]}" \
  --blockchain-specs "$BLOCKCHAIN_SPECS"

echo
if [[ "${PULSEVM_VERIFY_FIVE_NODE:-true}" == "true" ]]; then
  echo "==> Verifying all five custom-chain RPCs and replaying the common head"
  PULSEVM_FIVE_NODE_REPORT="${PULSEVM_FIVE_NODE_REPORT:-$BUILD_DIR/five-node-replay.json}" \
    "$REPO/scripts/verify-five-node-replay.sh" \
    "$RUNNER_ENDPOINT"
else
  echo "Cluster starting; five-node verification disabled (PULSEVM_VERIFY_FIVE_NODE=false)."
fi
echo
echo "The live gate proves five nodes independently decode and converge on one"
echo "PulseVM head. The block_log written by this local network is not an XPR"
echo "historical corpus. Full historical replay uses the ignored replay_testnet_blocks"
echo "test and JSON get_block fixtures fetched by scripts/fetch-blocks.sh:"
echo
echo "  PULSEVM_RPC_BLOCKS_DIR=/tmp/xpr-blocks \\"
echo "    cargo test -p pulsevm_core replay_testnet_blocks -- --ignored --nocapture"
echo
echo "An imported checkpoint starts the new Arena chain at its migration boundary;"
echo "full XPR historical parity additionally requires a captured block corpus and"
echo "system-contract replay validation."
wait $ANR_PID
