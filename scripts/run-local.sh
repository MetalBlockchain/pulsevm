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

echo "==> Ensuring metal-network-runner is installed"
if ! command -v metal-network-runner >/dev/null 2>&1; then
  go install github.com/MetalBlockchain/metal-network-runner@latest
  export PATH="$(go env GOPATH)/bin:$PATH"
fi

echo "==> Starting metal-network-runner server (background)"
metal-network-runner server --log-level info --port=":8080" --grpc-gateway-port=":8081" &
ANR_PID=$!
trap 'kill $ANR_PID 2>/dev/null || true' EXIT
sleep 3

echo "==> Launching a 5-node cluster running PulseVM from genesis.json"
metal-network-runner control start --log-level info \
  --endpoint="0.0.0.0:8080" \
  --number-of-nodes=5 \
  --metalgo-path "$METALGO_EXEC_PATH" \
  --plugin-dir "$BUILD_DIR" \
  --blockchain-specs "[{\"vm_name\": \"pulsevm\", \"genesis\": \"$REPO/genesis.json\"}]"

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
