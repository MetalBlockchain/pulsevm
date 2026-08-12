# Arena cutover — status & handoff

Goal: replace the C++ chainbase FFI (and, with it, boost) entirely with the
pure-Rust arena, with every feature covered and consensus-equivalent.

This note captures the state as of this branch so the remaining work — most of
which needs a machine that can build the C++ side — can be picked up directly.

## Where things stand

The pure-Rust store exists and is solid, but **C++ chainbase is still the sole
backend in every real build.** The arena runs only as a cross-checking *shadow*,
gated behind two off-by-default switches:

- Cargo feature `arena-shadow` (`pulsevm_ffi`, forwarded by `pulsevm_core`) —
  compiles the shadow in and mirrors writes into a `pulsevm_arena::Db`.
- Env var `PULSEVM_ARENA_READS` — lets a *subset* of reads be served from the
  arena instead of chainbase (flipped only on the tmpnet replay path,
  `controller.rs`).

### Covered and verified in pure Rust (builds/tests without any C++ toolchain)

- `pulsevm_arena` — index-addressed arena; chainbase-exact undo / `squash` /
  `commit` / `revision`; ordered + hash secondary indices; session-safe blob
  arena; snapshot + write-ahead-log persistence with crash recovery;
  `#[derive(ArenaObject)]`. Model-based differential proptests for the undo
  engine and the block/tx squash-on-commit / undo-on-failure pattern.
- `pulsevm_contractdb` — the full EOS contract-table API on the arena
  (`db_*_i64` + idx64/128/256/double/**long_double**), EOS-exact iterator
  handles, and RAM billing.
- `pulsevm_chaindb` — the **whole** arena-backed chain database: every chain
  table (accounts, account metadata, permissions, permission usage/links, code,
  transactions, contract tables + all secondary indices, resource
  limits/usage/state) and the create/modify/remove + read/positioning +
  undo/commit + persistence surface over them. This was previously
  `pulsevm_ffi/src/shadow.rs`, buildable only alongside the C++ tree; it is now
  a standalone pure-Rust crate (`pulsevm_ffi` re-exports it as `crate::shadow`).
  It is the single source of truth the cutover targets — the earlier
  contractdb-vs-shadow duplication is resolved in its favour for the system
  objects.

`cargo test -p pulsevm_arena -p pulsevm_contractdb -p pulsevm_chaindb` →
96 tests green, **no C++ toolchain required**.

### Added on this branch

- `idx_long_double` (float128) secondary index in `pulsevm_contractdb`, closing
  the last contract-table secondary-index parity gap (chainbase has
  `index_long_double_object`; the crate stopped at `double`). Ordering matches
  EOS `soft_long_double_less` (`f128_lt`); key crosses the API as the raw
  128-bit pattern (`u128`); RAM billed at `billable_size_v` = 144. New test file
  `tests/idx_long_double_tests.rs` (8 tests), including a sub-f64-ULP case that
  proves the full 113-bit significand is retained.

## What is NOT done (the cutover proper)

Roughly a third of the way. Remaining, in dependency order:

1. **Finish the arena read surface.** Only idx64 + primary `db_get_i64` /
   kv `next`/`previous` are served from the arena today. idx128/256/double/
   long_double are mirrored in `shadow.rs` but have no `Database` accessor and
   no serve branch in `apply_context.rs`; primary `db_lowerbound_i64` /
   `db_upperbound_i64` and all non-contract account/permission/permission-link
   authorization reads are cross-checked but never served. Mirror the idx64
   pattern (`database.rs` `arena_idx64_*` + `apply_context.rs` serve branches).

2. **Make the arena the write path**, not a mirror. Today every mutation is
   `chainbase-write → arena-replay` (`database.rs` calls into
   `pulsevm_chaindb`). Flip ownership; ensure the ~18 tables cover *all*
   chainbase tables (a few are still unmirrored, e.g. the global resource
   total-weight object noted in `pulsevm_chaindb`).

3. **Full session/undo integration in the controller.** The nested
   build/verify/accept session stack (`controller.rs`) must drive the arena
   transactionally on its own, not in lockstep behind chainbase.

4. **Cross-implementation `state_root`.** `Db::state_root` (`pulsevm_arena/src/db.rs`)
   currently hashes raw `BlobRef` (offset/len) and the whole blob arena — a
   canonical fingerprint *within one arena*, but not comparable to C++. For
   block-by-block equivalence it must hash blob *bytes* per object with blob
   offsets normalized out. Needs a per-object "which fields are blobs" hook on
   `ArenaObject` (+ the derive macro) and a rewrite of `Table::hash_state`.

5. **Extend the C++ differential harness.** `pulsevm_ffi/tests/diff_contract_iter.rs`
   drives contractdb and the FFI `Database` side by side, but only covers
   primary, RAM, and idx64. Add `compare_idx128/256/double/long_double`,
   mirroring `compare_idx64`, so the new secondary surfaces (incl. the
   long_double added here) are validated against chainbase. **This needs the
   C++ build** — it could not be compiled in the cloud session that wrote this.

6. **Port the remaining non-DB C++** so boost can actually go: the crypto
   wrappers (`CxxPublicKey`/signatures — a `pulsevm_crypto` crate already
   exists), the softfloat float128 builtins used by the WASM VM, the JSON query
   helpers (`get_table_rows`, `get_currency_*`, `get_account_info_*`,
   `get_table_by_scope`), and `pack_deltas` (state history).

7. **Delete the C++ tree**: `crates/pulsevm_ffi/pulsevm/**` (chainbase, boost
   submodule, softfloat, the `chain` library), the cmake `build.rs`, and the
   `cxx` bridge — only after 1–6 are green.

## Validating

The pure-Rust store needs no C++ and runs anywhere:

```
cargo test -p pulsevm_arena -p pulsevm_contractdb -p pulsevm_chaindb
```

The chainbase-equivalence checks need the C++ toolchain (boost + a C++20
compiler):

```
# build the C++ side needs boost checked out + a C++20 compiler
git submodule update --init --recursive
cargo test -p pulsevm_ffi --features arena-shadow            # shadow write/diff seam
cargo test -p pulsevm_ffi --features arena-shadow --test diff_contract_iter
```

The differential tests panic on any divergence from chainbase — that is the
equivalence bar (RAM billing, id assignment, iteration order, state root).
