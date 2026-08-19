# Pure-Rust chain database — completion status

PulseVM's chain database is now implemented entirely in Rust. The arena is the
sole execution, persistence, snapshot, and state-history backend. The former
chainbase implementation, vendored C++ tree, Boost dependency, CMake build, and
`cxx` bridge have been deleted.

## Runtime architecture

- `pulsevm_arena` provides typed tables, ordered and hashed secondary indexes,
  nested undo sessions, checkpoints, and incremental WAL persistence.
- `pulsevm_chaindb` defines every chain object and implements contract tables,
  permissions, resource accounting, transaction deduplication, genesis, and
  SHiP delta serialization over the arena.
- `pulsevm_database` is the public database facade used by `pulsevm_core`. The
  name reflects its current role; it contains no native bridge.
- `pulsevm_contractdb`, `pulsevm_crypto`, `pulsevm_softfloat`, `pulsevm_abi`,
  and `pulsevm_rpc` contain the other functionality formerly supplied by the
  native chain library.

There are no backend-selection feature flags or environment switches. Reads,
writes, genesis, undo sessions, snapshots, and state-history logs always use the
Rust implementation.

## Equivalence evidence

The replacement was developed against frozen outputs from the removed C++
implementation:

- The 1,697-block testnet replay matches every recorded per-table arena state
  root.
- All 1,696 post-genesis SHiP chain-state deltas match the frozen C++ output
  byte-for-byte.
- RPC JSON, ABI decoding, K1 crypto, and SoftFloat have committed known-answer
  fixtures captured before removal.
- Direct SHiP framing tests cover modified, removed, and created rows, repeated
  touches, nested-session squash, chainbase's reverse touch order, and stable
  full-snapshot ordering.
- Resource-accounting tests prove account CPU and NET limits reject overages
  before mutation and that missing/corrupt resource rows cannot fail open.
- The arena's model-based tests cover create/modify/remove, nested
  squash/undo/commit, secondary-index ordering, persistence, and torn WAL tails.

The full replay uses a frozen 1,697-block corpus. The runner validates its shape
and, when given an archive, requires SHA-256
`68bff604d1471d63aacc6bea7c997f5c97e53eddd6c9864238061083836d7572` before
extracting anything. With an unpacked corpus in `target/replay`, run:

```sh
scripts/run-replay-regression.sh
```

An archive can be passed directly:

```sh
scripts/run-replay-regression.sh /path/to/pulsevm-replay-fixtures.tar.gz
```

The ordinary pure-Rust database suites are:

```sh
cargo test -p pulsevm_arena -p pulsevm_contractdb -p pulsevm_chaindb -p pulsevm_database
```

Pull requests run the workspace tests, compile every target (including benches),
and apply `-D warnings` Clippy to the pure-Rust database replacement stack on
both amd64 and arm64. The consensus replay workflow uses the same two
architectures. Set the repository variable `PULSEVM_REPLAY_FIXTURE_URL` to the
published archive URL to make replay run on every push and pull request; it can
also be supplied manually through `workflow_dispatch`.

## Native dependencies that remain

PulseVM still uses Wasmer's LLVM backend for deterministic WebAssembly
compilation. Consequently builds require LLVM 22 and transitive Rust build
dependencies may invoke a C compiler, CMake, bindgen, or native libraries. These
are third-party runtime/toolchain requirements, not remnants of PulseVM's old
C++ database.

Removing every native compiler dependency would be a separate WASM-engine
migration. Any such change is consensus-sensitive and must repeat the
cross-architecture determinism tests and full replay.

## External fixture publication

The code-side replay automation is complete. The corpus itself remains outside
Git because it consists of captured testnet RPC responses. To activate the
push/PR replay job, publish the frozen archive and set its URL in the repository
variable described above. Its digest is pinned in the runner, so moving or
compromising the hosting location cannot silently change the consensus oracle.
