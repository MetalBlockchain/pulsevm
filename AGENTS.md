# PulseVM Agent Guide

This file applies to the entire repository. More specific `AGENTS.md` files, if added below this directory, override it for their subtree.

## Project overview

PulseVM is a Rust implementation of an EOSIO/Antelope-compatible WebAssembly VM running as a MetalGo subnet VM. Much of the code is consensus-critical: deterministic execution, authorization, resource accounting, serialization, database ordering, and state transitions must produce identical results on every node.

The code is authoritative. Start with `docs/README.md` for the design index, then read the relevant design document before changing protocol behavior.

## Repository map

- `crates/pulsevm`: VM binary, MetalGo integration, networking, JSON-RPC, mempool orchestration, and state-history WebSocket service.
- `crates/pulsevm_core`: block and transaction execution, authorization, resource accounting, WASM runtime, state sync, protocol features, and state-history logs.
- `crates/pulsevm_chain_types`, `pulsevm_crypto`, `pulsevm_name`, `pulsevm_serialization`: consensus wire and value types.
- `crates/pulsevm_arena`, `pulsevm_chaindb`, `pulsevm_database`: ordered state storage, persistence, undo sessions, and database facade.
- `crates/pulsevm_abi`, `pulsevm_rpc`: ABI decoding and RPC response formatting.
- `crates/pulsevm_wasm_validation`, `pulsevm_softfloat`: deterministic WASM validation and floating-point behavior.
- `crates/pulse`, `pulsevm_keosd`, `pulsevm_keosd_client`: CLI and wallet tooling.
- `crates/pulsevm_unittests`: higher-level execution and compatibility tests.
- `crates/pulsevm_e2e_boot`, `tests/e2e`: real multi-node MetalGo test fixtures and Go E2E tests.
- `crates/pulsevm_grpc/proto`: source protobuf definitions. Generated Rust is produced by `build.rs`; do not hand-edit generated output.

## Build prerequisites

- Use stable Rust for builds and tests unless a command below explicitly pins nightly.
- LLVM 22 and `libpolly-22-dev` are required. On standard Linux CI images, set `LLVM_SYS_221_PREFIX=/usr/lib/llvm-22` when it is not auto-detected.
- Protobuf compiler 27.1 is the CI version.
- Keep `Cargo.lock` respected with `--locked` in verification commands.
- Release artifacts must remain compatible with Ubuntu 22.04 / glibc 2.35.

## Formatting and style

- The repository uses Rust 2024.
- Format with the pinned nightly toolchain:

  ```sh
  cargo +nightly-2026-07-27 fmt --all -- --check
  ```

- Do not use stable `cargo fmt`; it ignores the unstable settings in `rustfmt.toml` and rewrites imports differently from CI.
- Follow the existing vertically grouped import style and keep comments focused on invariants and rationale.
- Prefer typed errors such as `ChainError` over panics. Never use `unwrap`, `expect`, unchecked indexing, or allocator-sized values on data controlled by transactions, peers, contracts, snapshots, ABIs, or RPC clients.
- Keep patches scoped. Do not mechanically reformat unrelated files or replace deterministic ordered collections with hash-based collections in consensus paths.

## Consensus and security rules

- If two released binaries could receive the same valid input and disagree about block validity, state, receipts, hashes, ordering, or observable execution output, treat the change as a protocol change. Use the protocol-feature framework described in `docs/protocol-features.md`, or explicitly document the coordinated-upgrade requirement.
- Never use wall-clock time, local machine performance, network timing, or other subjective state to decide first-time block validity.
- Validate peer blocks independently. Do not trust producer signatures, authorization claims, CPU/NET receipts, Merkle roots, schedules, or state-sync payloads merely because they are committed in a block or summary.
- Apply cheap objective bounds before expensive work or allocation. This includes signature recovery, decompression, collection allocation, ABI decoding, cryptography, WASM compilation, table scans, and snapshot downloads.
- All resource-accounting constants, WASM instruction/host-function costs, billing rules, and serialization layouts are consensus-sensitive. Add boundary tests whenever they change.
- Preserve exact wire formats: field order, variant tags, varint behavior, digest inputs, and canonical encodings. Reject trailing or malformed input where the surrounding format requires exact consumption.
- Preserve deterministic iteration and hashing. Use ordered indexes and `BTreeMap`/`BTreeSet` where iteration can affect consensus output.
- Arena undo sessions do not provide an automatic RAII rollback. Every fallible path after `arena_start_undo_session` must explicitly undo, squash, or commit exactly once.
- First-time validation and trusted replay are distinct. Authorization and deterministic resource remeasurement may only be skipped when the exact block was already validated by this node.
- State sync must authenticate canonical logical state before installation. Transport hashes alone do not prove consensus state.
- Keep controller and database locks short. Do not hold them across network waits or unbounded formatting/scanning, and paginate in the storage iterator rather than after collecting an entire table.
- Treat gossip, RPC, WebSocket/SHiP, protobuf, ABI, contract data, and snapshot bytes as hostile. Add timeouts, concurrency limits, and size limits at public boundaries.

## Testing

Start with the narrowest relevant test, then expand according to risk.

```sh
# Package or filtered regression tests
cargo test -p <crate> <test-filter> --locked

# Standard workspace gate
cargo test --workspace --locked

# Ensure benches/examples/all targets compile
cargo test --workspace --all-targets --locked --no-run

# Preview protocol profile; `nightly` here is a Cargo feature
cargo test -p pulsevm_core --locked --lib --features nightly
cargo check -p pulsevm --locked --features nightly
```

For database-stack changes, CI additionally requires:

```sh
cargo clippy -p pulsevm_arena -p pulsevm_chaindb -p pulsevm_database \
  --all-targets --all-features --locked -- -D warnings
```

For consensus changes, run the frozen replay regression when its fixture archive is available:

```sh
scripts/run-replay-regression.sh /path/to/pulsevm-replay-fixtures.tar.gz
```

Run `tests/e2e` only when MetalGo and the VM plugin are available. CI pins MetalGo `v1.13.5`; preserve that protocol compatibility unless the integration is deliberately upgraded.

## Test expectations

- Add a regression test that fails against the vulnerable or incorrect implementation.
- Test both sides of limits and activation boundaries, including malformed and adversarial input.
- For consensus changes, compare independently produced and validated blocks, receipts, roots, and persisted/reloaded state where applicable.
- Avoid tests that depend on timing, hash-map order, host architecture, or local timezone.
- Report commands actually run and any unavailable external fixtures or prerequisites in the final handoff.

## Documentation and pull requests

- Update the relevant file under `docs/` when behavior or an invariant changes. Keep code comments linked to the corresponding design section when practical.
- Explicitly call out consensus relevance, upgrade/activation requirements, security impact, and compatibility in the PR description.
- Do not commit build artifacts, node databases, logs, downloaded replay corpora, secrets, private keys, or local MetalGo binaries.
