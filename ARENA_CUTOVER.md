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

1. **Finish the arena read surface.** *Largely done — see "Layer 2" below.* All
   value-returning reads are now served + validated: every contract secondary
   index (idx64/128/256/double/long_double), primary rows, and the plain-value
   authorization reads (`is_account`, `is_account_privileged`,
   `lookup_linked_permission`). What remains are the reads that hand back a
   chainbase object reference (permission full authority, the `exec_one`
   account_metadata read fused with a write), which convert as part of the write
   flip, not as standalone serve branches.

2. **Make the arena the write path**, not a mirror. Today every mutation is
   `chainbase-write → arena-replay` (`database.rs` calls into
   `pulsevm_chaindb`). Flip ownership.

   **Table coverage is now complete for every live table.** The two live,
   mutable tables that were previously unmirrored are closed:
   - `global_property_object` (static `chain_config`) — `GlobalPropertyRow`,
     seeded from chainbase at genesis and updated by `set_global_properties`
     (the `setparams` intrinsic). Verified by `oracle_global_property_mirrors_setparams`
     and the `global_property` entry in `cross_impl_tables`.
   - `resource_limits_config_object` — `ResourceConfigRow` (elastic cpu/net
     params + the two averaging windows), seeded at genesis and updated by
     `set_block_parameters` end-of-block. Verified by the `resource_limits_config`
     entry in `cross_impl_tables` (exercised by `oracle_cross_impl_full_state_root`,
     which builds a block).

   The remaining three chainbase indices are **intentionally not mirrored** and
   are safe to leave until the write flip (document, don't port blindly):
   - `protocol_state_object` — genesis-only in C++, read-only thereafter
     (activated protocol features / key-type count); PulseVM activates none, so
     it never changes. Mirror it only if/when a protocol-feature activation path
     lands.
   - `database_header_object` — a genesis-only db-version sigil, not consensus
     state (leap excludes it from comparison too).
   - `account_ram_correction_object` — registered but **never written** in this
     tree (deferred-trx RAM correction is unsupported); dead state.

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

---

# Layer 2 — taking C++ off the execution path (design & sequencing)

Goal restated: the arena becomes the sole backend **execution reads and writes
from**, while C++ chainbase stays compiled and runs in parallel purely as the
comparison oracle (`note_pos` / `note_noncontract` / `cross_impl_tables`). The
C++ source tree is *kept*, not deleted — deletion (step 7 above) is out of scope.

## Where execution stands now

Everything that returns a **value** is already served from the arena under
`PULSEVM_ARENA_READS` and validated against chainbase:

- Contract secondary indices — idx64/128/256/double/long_double
  (`find_secondary`/`find_primary`/`lowerbound`/`upperbound`), each with a
  Database `arena_idx*` accessor and an `apply_context` serve branch, proven by
  the `idx*_read_accessors_match_chainbase` differential tests.
- Primary rows — `db_get_i64`/`next`/`previous` serve; `db_lowerbound/upperbound`
  cross-check the landing primary (the observable row flows through the served
  `db_get_i64`).
- Plain-value authorization reads — `is_account`, `is_account_privileged`,
  `lookup_linked_permission`. `find_account` is retired from execution entirely
  (every caller only tested existence); its object read survives only in tests.

## What still reads/writes C++ during execution

1. **`account_metadata` in `exec_one`** (`apply_context.rs`). *Mostly converted.*
   The paired write is arena-owned: `next_recv_sequence` now takes the account
   *name*, resolves and bumps `recv_sequence` inside the FFI layer (no
   `&AccountMetadataObject` escaping into execution), and serves the incremented
   value from the arena. The receipt scalars — `is_privileged`, `code_sequence`,
   `abi_sequence` — are served too (`is_account_privileged`,
   `account_metadata_code_abi_sequence`). The only field still taken off the
   chainbase object is `code_hash`, which flows straight into the wasm runtime
   (`Id::from` + the code-object lookup); it converts with the code-object read
   surface, not here.

2. **Permission reads needing the full authority.** *Authorization satisfaction
   is now served.* `DbRead::permission_authority` decodes `PermissionRow.auth`
   back into an owned `Authority`, cross-checked on the canonical encoding, and
   `authority_checker.rs` reads through it — so under `PULSEVM_ARENA_READS` the
   whole satisfaction walk runs on arena-served authorities
   (`oracle_permission_authority_serves_from_arena`). What remains are the
   permission-object reads fused with a write: `.get_authority().get_billable_size()`
   and `.get_id()` (`pulse_contract.rs` updateauth/linkauth), `.get_name()`
   (`authorization_manager.rs`), and `.satisfies(other, db)` (a C++ method). These
   convert with the write flip, not as standalone serve branches.

3. **Iterator handles.** The `*IteratorCache` handles (including the end-iterator
   encoding) are minted by chainbase. Contracts observe and compare them, so the
   arena must mint its own handles with the identical encoding before it can own
   iteration.

4. **Writes.** Every mutation is still `chainbase-write -> arena-replay`. The
   arena is a mirror, not the source of truth.

## Sequencing (each step stays behind the flag + cross-checks until green)

1. **Arena authority decode.** *Done.* `DbRead::permission_authority` decodes
   `PermissionRow.auth` into the `Authority` the checker uses and serves it under
   `PULSEVM_ARENA_READS`; `authority_checker.rs` reads through it. The remaining
   permission-object reads (`get_id`/`get_name`/`get_billable_size`/`satisfies`)
   are fused with writes and convert with the write flip below.

2. **Co-convert `account_metadata` read+write in `exec_one`.** *Done bar the
   wasm code hash.* `next_recv_sequence` is now name-based, arena-served, with no
   chainbase reference escaping; `is_privileged`/`code_sequence`/`abi_sequence`
   are served scalars. This is the first place the arena owns a read and its
   paired write together — the template for the write flip. Only `code_hash`
   remains, and it moves with the code-object read surface (step 3-adjacent).

3. **Arena-owned iterator handles.** The largest piece. Mint handles matching
   chainbase's encoding; validate with `diff_contract_iter` (iterator-handle
   equality is already its bar) extended past idx64.

4. **Flip write-ownership.** Invert the mirror: the arena writes first and is the
   source of truth; chainbase becomes the parallel shadow. Every create/modify/
   remove already mirrors both ways, so this is inverting which side is
   authoritative, table by table, cross-checked each block.

5. **Controller drives the arena undo/session stack** directly, not in lockstep
   behind chainbase's RAII sessions.

6. **Default `PULSEVM_ARENA_READS` on.** C++ now runs only to compare. Acceptance
   gate: replay the alpine testnet history (1697 blocks, chain-id
   `193526980f523c07a567dda80f5f543e2356518ce1475cf3e03d98ca740b3f67`) with both
   backends live, asserting per-block `cross_impl_tables` equality end to end.

## The validation bar (unchanged, just widened)

- `note_pos` / `note_noncontract`: every served read must equal chainbase, always.
- `diff_contract_iter`: iterator-handle + key equality vs chainbase.
- `cross_impl_tables`: whole-state per-block equality (now includes
  `global_property` and `resource_limits_config`).
- Testnet replay: the end-to-end consensus-equivalence gate.

Nothing advances to "arena-primary" for a given surface until its cross-check has
been green across a full testnet replay.
