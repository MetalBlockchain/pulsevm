# pulsevm_arena

A native Rust state store that replaced the C++ chainbase FFI while preserving
its consensus-visible behavior.

## The idea

chainbase is fast partly because its containers live in one mapped segment and
are addressed by self-relative pointers, so the in-memory bytes are the on-disk
format. Replicating that in Rust means self-referential, relocatable, move-unsafe
structures — a large `unsafe` project, essentially re-deriving boost.interprocess.

This crate takes the other road: **address objects by index, not pointer.** An
array index is already relocation-invariant, so a store of fixed-size POD objects
in one contiguous arena (the slot number *is* the id) holds no absolute
addresses. That buys chainbase's two wins in safe Rust:

- **Intrusive-quality reads** — a secondary index maps `key -> id`, and the
  primary is an O(1) slot, so a lookup is one tree descent plus an array index,
  and reads hand out references (no clone).
- **Cheap persistence** — the arena is pointer-free, so a snapshot is a byte
  copy, not a serialization pass, and the same layout can be memory-mapped for
  O(dirty) flushes.

## What's here

- [`Table<T>`](src/table.rs) — the index-addressed arena: rows in a contiguous
  `Vec` keyed by id (tombstone on remove, ids never reused unless undone),
  ordered-unique secondary indices, and the full chainbase undo lifecycle
  (create/modify/remove, `squash`, `commit`, `undo_all`), single-threaded, no
  lock.
- [`Db`](src/db.rs) — a set of tables sharing one revision/undo lifecycle; a
  session spans every table so a rejected block reverts them together. Plus raw
  snapshot `save`/`load`.
- [`ArenaObject`](src/object.rs) — the object trait: fixed-size POD (`zerocopy`),
  with a built-in `by_id` index and declared secondary indices.

Tests: [`table_tests.rs`](tests/table_tests.rs), [`db_tests.rs`](tests/db_tests.rs).
Benchmark: `cargo bench -p pulsevm_arena`.

## Historical performance snapshot

| operation | arena | former C++ baseline |
|---|---|---|
| insert | 57 ns | ~135 ns |
| find by id, 100k rows | **2 ns** (O(1)) | ~58 ns |
| find by name, 100k rows | 34 ns | 58 ns |
| undo (100 creates → commit) | 5.9 µs | ~14 µs |
| snapshot save, 100k | 1.9 ms (incl. disk) | — |
| snapshot load, 100k | 4.1 ms | — |

## Integration status

The arena is the active PulseVM database engine. `pulsevm_chaindb` defines the
chain tables and `pulsevm_database` exposes the controller-facing facade.
Consensus equivalence is covered by unit/property tests and the 1,697-block
testnet replay, including byte-for-byte SHiP delta comparison against the frozen
reference output.

Possible future optimizations include:

- **mmap-backed arena** — O(dirty) flush / O(1) open; reuses this exact layout
  since it is already pointer-free.
- **Variable-length fields** — a per-table blob arena addressed by `(offset,
  len)`, for objects that carry abi/code/KV bytes (POD objects are fixed-size).
- **A `#[derive]` macro** to reduce the boilerplate in `ArenaObject`
  implementations.

See `docs/rust-chainbase-arena-spike.md` for the investigation that motivated
this and the fuller roadmap.
