# PulseVM database facade

This crate exposes the database API used by `pulsevm_core`. It delegates chain
state to `pulsevm_chaindb`, persistence to the arena checkpoint/WAL machinery,
and RPC formatting to the pure-Rust ABI and RPC crates.

Despite descending from the former bridge crate, it contains no FFI or C++.
The database is safe Rust and is cheaply cloneable; clones share the same
`pulsevm_chaindb::ChainDatabase` handle.

The default-off optimistic API provides frozen read snapshots,
transaction-private contract-row overlays, deterministic dependency validation,
bounded worker execution, canonical-order apply, and automatic serial fallback.
See
[`docs/optimistic-parallel-execution.md`](../../docs/optimistic-parallel-execution.md)
for its current scope and the remaining gates before general VM block
execution can use it.

Run its tests with:

```sh
cargo test -p pulsevm_database
```

Run its serial/optimistic coordinator benchmarks with:

```sh
cargo bench -p pulsevm_database --bench optimistic_execution --locked
```
