# PulseVM database facade

This crate exposes the database API used by `pulsevm_core`. It delegates chain
state to `pulsevm_chaindb`, persistence to the arena checkpoint/WAL machinery,
and RPC formatting to the pure-Rust ABI and RPC crates.

Despite descending from the former bridge crate, it contains no FFI or C++.
The database is safe Rust and is cheaply cloneable; clones share the same
`pulsevm_chaindb::ChainDatabase` handle.

Run its tests with:

```sh
cargo test -p pulsevm_database
```
