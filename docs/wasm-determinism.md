# WASM execution determinism

Contract execution must be bit-identical on every node, or the chain forks. This
note records where PulseVM stands on that, answering the three concerns raised,
and what this branch changed. All of it lives in
[`wasm_runtime.rs`](../crates/pulsevm_core/src/chain/wasm_runtime.rs).

## TL;DR

- **Floats are deterministic.** 32/64-bit ops run with NaN canonicalization on;
  128-bit / `long double` goes through Berkeley SoftFloat (bit-exact), same as
  EOSIO. No fast-math.
- **The wasm feature set is now pinned.** Previously we inherited
  `Features::default()`, which turns `threads` and `simd` on and can gain more in
  a future wasmer release — an upgrade could silently change consensus. It's now
  fixed explicitly and guarded by a test.
- **Compiled modules are already cached in memory** (per-code LRU) and behind a
  warm-store instance pool. Persisting them across restarts is an optional
  load-time optimization, not a determinism issue.

## 1. Store compiled wasm in memory vs. compile on the go

Already the case. `WasmRuntime` keeps an LRU **module cache** keyed by code hash
(1024 entries): the first execution of a given contract compiles it, every later
one reuses the compiled `Module`. On top of that a thread-local **warm-store
pool** keeps the ~150-entry host-import table built, which is the bulk of
per-action setup. So we do **not** recompile per call.

What we don't do yet is persist compiled artifacts **across process restarts** —
on reopen, each contract recompiles on first use. That could be moved to
`setcode` time (compile once, cache `Module::serialize` bytes on disk), making
`setcode` slightly slower and cold-loads faster.

- Determinism impact: **none.** Same module bytes → same execution regardless of
  when compiled.
- Caveat if we add it: a serialized artifact is tied to an exact
  `(wasmer version, LLVM version, target triple)`. A persisted cache **must** be
  keyed on those and invalidated on any change, or a stale artifact would run
  after an upgrade. Deferring this is fine.

## 2. Determinism across an LLVM (or wasmer) upgrade

The key point: determinism does **not** require byte-identical machine code
across LLVM versions. It requires identical *observable* execution — same
results, same traps, same gas. WASM semantics guarantee that as long as four
things hold:

1. **The enabled feature set is fixed.** This was the gap. `Module::new` used the
   engine's default features, and `Features::default()` in wasmer 7.2 enables
   `threads` and `simd` (and a future release could enable e.g. `relaxed_simd`).
   A wasmer/LLVM bump could therefore change what contracts may do — a silent
   consensus change. **Fixed on this branch:** `deterministic_features()` pins
   every proposal explicitly, and `pinned_features_stay_deterministic` fails CI if
   any value drifts.
2. **NaN payloads are canonicalized** — `canonicalize_nans(true)`, already on.
3. **No fast-math.** wasmer's LLVM backend must emit spec-compliant wasm and does
   not enable fast-math; the aggressive opt level does not reorder FP ops.
4. **Metering is unchanged** — `COST_FUNCTION` + the metering middleware live in
   our code, pinned, independent of LLVM.

**Recommendation:** treat any wasmer/LLVM version bump as a consensus change —
the versions are pinned to exact `7.2.0` in `Cargo.toml`; before adopting a new
one, re-run the differential replay. The feature test is the tripwire for the
most likely silent regression.

## 3. Is the floating-point logic deterministic?

Yes.

- **32/64-bit (`f32`/`f64`)** — native wasm ops, deterministic per IEEE-754 and
  the wasm spec, with NaN canonicalization removing the one source of
  platform-specific nondeterminism (NaN payload bits). No fast-math, so no
  reassociation/contraction.
- **128-bit / `long double` (`float128`)** — not hardware. The `__addtf3`,
  `__multf3`, `__divtf3`, `__subtf3`, the `__float*`/`__fix*` conversions and the
  `__eqtf2`/`__letf2`/… comparisons use the pure-Rust `pulsevm_softfloat` port of
  **Berkeley SoftFloat Release 3e**. Its output is pinned to vectors captured
  from the removed reference implementation.
- **128-bit integer builtins** (`__ashlti3`, `__multi3`, …) — pure Rust
  `u128`/`i128`, deterministic.

So EOSIO's softfloat requirement is met for the 128-bit path; for 32/64-bit, NaN
canonicalization plus spec semantics remove the need for softfloat, which is the
modern-runtime approach the concern anticipated.

### Floats also order storage — the `idx_double` / `idx_long_double` indexes

Float determinism isn't only about contract *math*; a contract can use an
IEEE `double` / `long double` as a **secondary index key**, and the *ordering* of
those keys must be identical everywhere. Two subtleties here:

- **The comparator.** The reference implementation ordered these indexes with a
  raw `f64_lt` / `f128_lt`. The Rust database reproduces that order with an
  IEEE-754 **total order** (`total_cmp`-style, `-0.0` folded onto `+0.0`) in
  [`pulsevm_chaindb`](../crates/pulsevm_chaindb/src/lib.rs). These agree on every value
  **except NaN** — and NaN is where it bites.
- **NaN is not a valid key, and nothing was stopping it.** `f*_lt(NaN, x)` and
  `f*_lt(x, NaN)` are both false, so a NaN key breaks the container's
  strict-weak ordering and orders differently from the arena's total order. The
  reference `db_idx_*` intrinsics
  reject a NaN secondary key; that guard had not been ported, so a contract
  could store one and diverge from the reference chain. **Fixed on this branch:** `reject_nan_f64`
  / `reject_nan_f128` reject a NaN at the host boundary for every float-secondary
  intrinsic that takes a key from the contract (`store`, `update`,
  `find_secondary`, `lowerbound`, `upperbound`, both widths). With NaN kept out,
  the two stores agree trivially and we match the reference's accept/reject.

## What changed on this branch

`wasm_runtime.rs`:

- `deterministic_features()` — the pinned wasm feature set. Off: `threads`,
  `simd`, `relaxed_simd`, and the rest of the advanced proposals. On (all
  deterministic, all emitted by the contract toolchain): `reference_types`,
  `bulk_memory`, `multi_value`, `extended_const`. Disabling `reference_types`
  or `bulk_memory` fails to validate real contracts (clang/CDT uses the
  reference-types `call_indirect` encoding and `memory.copy`).
- `deterministic_engine()` — one place that builds the LLVM engine with NaN
  canonicalization, aggressive opt, metering, and the pinned features; used by
  the compile path. Removed a dead compiler that `new()` built and never used.
- `pinned_features_stay_deterministic` test — locks the set so any future flip is
  a deliberate, reviewed change.

[`database.rs`](../crates/pulsevm_core/src/chain/webassembly/database.rs):

- `reject_nan_f64` / `reject_nan_f128` — reject a NaN secondary key at the host
  boundary, on all ten float-secondary intrinsics (see the storage-ordering note
  above). Tests `f64_secondary_rejects_nan_only` / `f128_secondary_rejects_nan_only`
  pin the detection (infinities and both zeros stay allowed).

## Determinism tests

- `canonicalize_nans_masks_nan_payloads` — compiles a tiny module on the real
  `deterministic_engine` and feeds a float op several non-canonical NaN patterns;
  each must come back as the single wasm canonical NaN. Verified to *fail* with
  `canonicalize_nans` off, so it actually pins the setting (not a tautology).
- `softfloat_128bit_math_is_exact_and_stable` — `long double` arithmetic through
  Berkeley SoftFloat is bit-exact, and an inexact result / a NaN are the *same*
  bits every call.
- `pinned_features_stay_deterministic` — the wasm feature set can't silently drift.
- `f64_secondary_rejects_nan_only` / `f128_secondary_rejects_nan_only` — the NaN
  secondary-key guard's *classifier* (infinities and both zeros stay allowed).
- `nan_secondary_key_rejected_through_host_boundary` — the guard's *wiring*: a
  minimal hand-built contract per intrinsic writes a NaN and calls it, and the
  transaction must fail with the secondary-key message. Covers all ten
  `idx_double` / `idx_long_double` sites, so dropping a guard from any one is
  caught (verified: removing one fails the test, naming that intrinsic). The
  classifier tests alone can't catch a missing call site — which is how the
  original gap looked.
- `contract_execution_is_reproducible` — the same action on two independent
  controllers (sharing the thread-local warm-store pool + module cache) yields
  byte-identical results; `pg` self-validates its db results, so this also proves
  warm-store reuse across instances stays clean. It also pins the action-receipt
  digest to a committed **golden constant**: the unit-test CI matrix runs on
  amd64 and arm64, so both arches checking the same constant is what actually
  gates *cross-architecture* determinism of a full contract run — a real
  divergence would land on one arch only.
- The **1,697-block golden replay** is the end-to-end check: the Rust database
  matches the state roots captured while the reference backend was still
  available. It is `#[ignore]`d and reads a block set from outside the repo
  (`PULSEVM_RPC_BLOCKS_DIR` / `PULSEVM_REPLAY_BLOCK_LOG_DIR`), so it is a manual
  gate, not a CI job — see below.

## Validation

- The core library tests pass, including the determinism tests above and real
  CDT-compiled contract execution (`pulse_token`, `test_api_db`,
  `test_api_multi_index` — the last exercises the `idx_double`/`idx_long_double`
  paths with real keys) under the pinned engine.
- **CI runs these on two architectures.** `.github/workflows/test.yml` runs
  `cargo test` on an amd64 and an arm64 runner, so every determinism test — the
  canonical-NaN and softfloat *golden constants*, the feature-set tripwire, the
  NaN-guard classifier and wiring tests, and the golden receipt digest — is
  checked independently on each arch on every push and PR. Two arches agreeing on
  the same committed constants is the cross-architecture determinism gate.
- **1,697-block golden replay** (Rust arena state root against the frozen
  reference root at every block): 1:1 with the pinned feature set — every real
  contract on the chain (system contract, `pulse.token`) compiles and executes
  identically. _(Run with onblock gated and blocks re-signed, since this base
  carries block-signature verification but not the replay-harness re-sign — both
  are unrelated to the wasm change.)_

## Open items / recommendations

- **Get the full replay into CI.** The unit-level determinism gate is now
  cross-arch, but the end-to-end 3631-block replay still needs a block set that
  lives outside the repo, so it can't run on a stock runner. To make it a CI job:
  commit a compact fixture block set (or fetch a pinned one), add a leg that
  runs the `#[ignore]`d replay against it,
  and — since the payoff is cross-arch — run that leg on both amd64 and arm64.
  This also automates "wasmer/LLVM bump = re-run the replay": a version drift that
  the feature test can't see would move a state root and fail the job.
- Optionally persist compiled modules at `setcode`, version-keyed (perf only).
- Gate wasmer/LLVM upgrades on a full differential replay; keep the feature test.
- The runtime feature set is now consensus state — any change rolls out
  network-wide, in lockstep.
