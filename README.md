# PulseVM

[![Code coverage](https://codecov.io/gh/MetalBlockchain/pulsevm/branch/main/graph/badge.svg)](https://codecov.io/gh/MetalBlockchain/pulsevm)

PulseVM is a Rust implementation of an EOSIO/Antelope-compatible WebAssembly virtual machine for Metal Blockchain. It brings the account, permission, action, and smart-contract model familiar to EOSIO, Antelope, and XPR Network developers to a blockchain running as a MetalGo subnet VM.

PulseVM executes contracts and manages chain state. MetalGo hosts the VM as a plugin and drives consensus and block acceptance. This repository includes the VM, a command-line client, a wallet service, and the libraries and tests behind them.

## What it provides

- **WebAssembly smart contracts.** A Wasmer runtime with an LLVM backend, EOSIO-style host functions, ABI support, account permissions, and contract tables.
- **Deterministic resource accounting.** CPU billing uses operation costs for WASM execution and metered host functions. NET accounts for transaction size, and RAM tracks persistent state usage.
- **MetalGo integration.** A gRPC VM plugin with transaction gossip, mempool admission, block construction, validation, and acceptance.
- **Persistent chain state.** Ordered database storage, undo sessions, block replay, snapshots, and state synchronization.
- **Application interfaces.** JSON-RPC methods for submitting transactions and querying chain state, plus a state-history WebSocket service for traces and table deltas.
- **Developer tools.** The `pulse` CLI for accounts, contracts, transfers, and wallet operations, and `pulse-keosd` for local key management and signing.

### Compatibility and consensus

PulseVM aims for EOSIO/Antelope contract compatibility, with deliberate differences in consensus integration and resource billing. CPU usage is measured in deterministic operation units; some compatibility fields retain names such as `cpu_usage_us`. Applications connect through PulseVM's `pulsevm.*` JSON-RPC methods.

Block acceptance is driven by MetalGo consensus. The VM checks its mempool every 500 ms to request block production when transactions are available; this interval is not a finality guarantee.

Changes to execution, billing, serialization, or state ordering can change consensus. The [protocol-feature framework](docs/protocol-features.md) defines how upgrades are scheduled by block height. The current implementation supports protocol version 1 (`Baseline`).

## Build from source

Linux builds are tested on x86-64 and ARM64. Release binaries are built against Ubuntu 22.04 to retain compatibility with glibc 2.35.

Install these prerequisites before building:

| Dependency | Requirement |
| --- | --- |
| Rust | Stable toolchain with Rust 2024 support, installed through `rustup` |
| LLVM | LLVM 22 development libraries and `libpolly-22-dev` |
| Protobuf | `protoc`; CI uses version 27.1 |
| Native build tools | C/C++ compiler, CMake, and `pkg-config` |
| Native libraries | zlib, OpenSSL, and zstd development packages |

On Ubuntu, the corresponding native packages are `build-essential`, `cmake`, `pkg-config`, `llvm-22-dev`, `libpolly-22-dev`, `zlib1g-dev`, `libssl-dev`, `libzstd-dev`, and `zstd`. LLVM 22 packages require the LLVM APT repository for your Ubuntu release. See the [release build workflow](.github/workflows/build.yml) for the complete CI setup, including installation of LLVM and Protobuf.

```bash
git clone https://github.com/MetalBlockchain/pulsevm.git
cd pulsevm

export LLVM_SYS_221_PREFIX=/usr/lib/llvm-22
cargo +stable build --release --locked -p pulsevm -p pulse -p pulsevm_keosd
```

If LLVM is installed elsewhere, set `LLVM_SYS_221_PREFIX` to that installation's prefix.

The build produces:

| Binary | Purpose |
| --- | --- |
| `target/release/pulsevm` | VM plugin launched by MetalGo |
| `target/release/pulse` | Command-line client |
| `target/release/pulse-keosd` | Wallet service |

## Run a local network

In addition to the build dependencies, you need a compiled MetalGo binary and `metal-network-runner` on your `PATH`. CI tests against MetalGo **v1.13.5**; the node and VM must agree on rpcchainvm plugin protocol **43**.

From the repository root, stage the compiled VM under the ID MetalGo uses to discover it:

```bash
mkdir -p build
cp target/release/pulsevm build/rXcAFxZvio99epp6TzEwYfexCfPAbJuBTMsjUUoiT7PkVykNs
```

Start the network runner in one terminal:

```bash
metal-network-runner server \
  --log-level info \
  --port=":8080" \
  --grpc-gateway-port=":8081"
```

In another terminal, from the repository root, set the path to your MetalGo binary and launch a five-node network using the included [genesis configuration](genesis.json):

```bash
export METALGO_EXEC_PATH=/absolute/path/to/metalgo

metal-network-runner control start \
  --log-level info \
  --endpoint="0.0.0.0:8080" \
  --number-of-nodes=5 \
  --metalgo-path "$METALGO_EXEC_PATH" \
  --plugin-dir "$PWD/build" \
  --blockchain-specs "[{\"vm_name\":\"pulsevm\",\"genesis\":\"$PWD/genesis.json\"}]"

metal-network-runner control status --endpoint="0.0.0.0:8080"
```

The [local-network helper](scripts/run-local.sh) automates the build, plugin staging, runner startup, and network launch. It also installs `metal-network-runner` through Go if the runner is missing.

### Query the chain

Use a node's HTTP address and the blockchain ID reported by the network runner to construct the RPC URL:

```text
http://<node-host>:<node-port>/ext/bc/<blockchain-id>/rpc
```

The node address is separate from the network runner's control endpoint. The blockchain ID in the URL is also distinct from the hexadecimal transaction-signing `chain_id` returned by `pulsevm.getInfo`.

Set `PULSEVM_RPC_URL` to that URL, then query through the CLI or JSON-RPC:

```bash
export PULSEVM_RPC_URL='http://<node-host>:<node-port>/ext/bc/<blockchain-id>/rpc'

./target/release/pulse --url "$PULSEVM_RPC_URL" get info

curl --silent --show-error "$PULSEVM_RPC_URL" \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":[]}'
```

Run `./target/release/pulse --help` to explore the client commands. The [RPC service definitions](crates/pulsevm/src/chain/service.rs) list the available API methods and their parameters.

## Development and testing

The [coverage workflow](.github/workflows/coverage.yml) reports Rust workspace
coverage to Codecov on pushes to `main` and pull requests. Checks allow at most a
one-percentage-point drop in overall coverage and require 80% coverage of changed
executable lines. See the [coverage guide](docs/code-coverage.md) for repository
setup, scope, and local reports.

Use stable Rust for builds and tests, and preserve the dependency versions in `Cargo.lock` with `--locked`.

```bash
# Start with a relevant package.
cargo +stable test -p pulsevm_core --locked

# Run the workspace tests and compile every target.
cargo +stable test --workspace --locked
cargo +stable test --workspace --all-targets --locked --no-run
```

Formatting uses a pinned nightly toolchain because the repository's rustfmt configuration requires unstable options:

```bash
rustup toolchain install nightly-2026-07-27 --profile minimal --component rustfmt
cargo +nightly-2026-07-27 fmt --all -- --check
```

The `nightly` **Cargo feature** is separate from the Rust toolchain: it controls compilation of preview protocol implementations, while the chain's upgrade schedule controls activation. See [protocol features](docs/protocol-features.md) for validation commands and rollout rules.

The [E2E suite](tests/e2e) boots real MetalGo nodes and requires a built VM plugin; its full setup is in the [E2E workflow](.github/workflows/e2e.yml). Consensus changes should also run the [frozen replay regression](scripts/run-replay-regression.sh) when the external fixture archive is available:

```bash
scripts/run-replay-regression.sh /path/to/pulsevm-replay-fixtures.tar.gz
```

## Explore the code

| Area | Location |
| --- | --- |
| VM integration, networking, RPC, and state-history service | [`crates/pulsevm`](crates/pulsevm) |
| Execution, authorization, resource accounting, and WASM runtime | [`crates/pulsevm_core`](crates/pulsevm_core) |
| Ordered storage, persistence, and database facade | [`pulsevm_arena`](crates/pulsevm_arena), [`pulsevm_chaindb`](crates/pulsevm_chaindb), [`pulsevm_database`](crates/pulsevm_database) |
| Consensus types, cryptography, and serialization | [`pulsevm_chain_types`](crates/pulsevm_chain_types), [`pulsevm_crypto`](crates/pulsevm_crypto), [`pulsevm_serialization`](crates/pulsevm_serialization) |
| ABI handling and RPC formatting | [`pulsevm_abi`](crates/pulsevm_abi), [`pulsevm_rpc`](crates/pulsevm_rpc) |
| WASM validation and deterministic floating point | [`pulsevm_wasm_validation`](crates/pulsevm_wasm_validation), [`pulsevm_softfloat`](crates/pulsevm_softfloat) |
| CLI and wallet | [`pulse`](crates/pulse), [`pulsevm_keosd`](crates/pulsevm_keosd), [`pulsevm_keosd_client`](crates/pulsevm_keosd_client) |
| Execution and compatibility tests | [`crates/pulsevm_unittests`](crates/pulsevm_unittests) |

Start with the [design documentation index](docs/README.md), then read the relevant guide:

- [Resource model](docs/resource-model.md): CPU, NET, and RAM accounting.
- [Host-function costs](docs/intrinsic-cost-model.md): pricing and calibration.
- [WASM determinism](docs/wasm-determinism.md): runtime features, floating point, and replay.
- [Mempool admission](docs/mempool-admission.md): preflight checks, capacity, expiry, and concurrency.
- [Protocol features](docs/protocol-features.md): consensus versions and coordinated upgrades.

## Contributing

Read [AGENTS.md](AGENTS.md) for repository conventions, security invariants, and required checks. Keep changes scoped, add regression tests for fixes, and update the relevant design document when behavior changes. Pull requests that affect consensus should explain compatibility and upgrade or activation requirements.

The code is authoritative when it differs from the design notes.

## License

PulseVM is licensed under the [MIT License](LICENSE), with attribution to Metallicus and the Antelope/EOSIO projects on which it is based.
