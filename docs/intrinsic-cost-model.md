# Host-intrinsic CPU cost model

WASM operators are metered by the middleware; the points a call consumes become
its billed CPU (`run()` seeds the budget from the account's `cpu_limit` and
returns what was spent, which lands in the transaction receipt). A host intrinsic
does native work the operator metering can't see, so each one bills itself in the
same points via `WasmContext::charge`, using the table in
`crates/pulsevm_core/src/chain/webassembly/cost.rs`. Because those points are
billed CPU and billed CPU is committed to the block, **the table is a consensus
rule** — every node must charge identically, and a change is a coordinated
upgrade, like the pinned wasm feature set.

The values shipped initially were hand-picked, scaled by eye to the operator
table. This document records how to derive them from measurement instead, what a
first measurement found, and the calibration decision that measurement forces.

## Method (a stripped-down NEAR runtime-params-estimator)

The estimator is an ignored test:

```
cargo test --release -p pulsevm_core --lib estimate_intrinsic_costs \
  -- --ignored --nocapture
```

1. **Anchor.** Run a compute-bound wasm loop on the real metered LLVM engine and
   read *both* wall time and points consumed from the metering middleware. Their
   ratio is ns-per-point on this machine. This ties intrinsic prices to the same
   scale the operator table already bills in, without hand-computing any operator
   cost.
2. **Measure.** Time each intrinsic's native work across input sizes; base is the
   fixed cost at size 0, the per-byte slope is a least-squares fit over the linear
   region (≥ 1 KiB).
3. **Convert.** `points = ns / ns_per_point`, times a **safety multiplier** (3×,
   as NEAR historically used) so a point is an *upper bound* on real time. An
   under-charge is a DoS hole; an over-charge only costs fairness.

The absolute ns are hardware-specific; the ratios and the resulting table are
what get pinned.

## First measurement (Apple silicon, wasmer-LLVM release, 3× safety)

Anchor: **1 point ≈ 0.0264 ns** (≈ 37,900 points/µs).

| intrinsic   | base (pts) | per-byte (pts) | shipped base / per-byte | under-charge |
|-------------|-----------:|---------------:|------------------------:|-------------:|
| sha256      |      2,026 |          34.75 |                  30 / 1 |         ~35× |
| sha512      |      5,816 |          63.96 |                  30 / 1 |         ~64× |
| sha1        |      5,533 |          81.15 |                  30 / 1 |         ~81× |
| ripemd160   |     16,604 |         275.40 |                  30 / 1 |        ~275× |
| memcpy      |        293 |           9.81 |                  10 / 1 |         ~10× |
| recover_key |  1,643,577 (fixed) |        — |                    2,000 |        ~820× |

(sha256/sha512 use the `asm` backend and are fast per byte; sha1/ripemd160 have
no asm and are slower; `recover_key` is a full secp256k1 recovery, ~14.5 µs.)

The hand-picked table under-charges the exploitable paths by **30–800×**. That
alone retires "scale it to the operator costs by eye" as indefensible.

## What the measurement forces: a unit/limit reconciliation

The point unit is very fine — ~26 ps — because per-op integer metering needs the
cheapest operator to cost ≥ 1 point, and the cheapest op is sub-nanosecond. That
is fine for operators, but it means real intrinsic work is a large number of
points, and that collides with the configured CPU limits:

- `recover_key` alone is ~1.6M points. Genesis
  `max_transaction_cpu_usage = 150000` would reject any transaction that recovers
  a key — you cannot do a 14 µs operation inside a 4 µs budget.
- More broadly, the genesis limits look like EOSIO **microsecond** values
  (`150000`, `200000`) but are consumed as raw **points** at ~26 ps each — off by
  ~38,000×. This is why the live-cluster bring-up had to raise
  `max_transaction_cpu_usage` to 1e9 just to deploy a contract.

So the intrinsic table can't be fixed in isolation. The three quantities —
operator costs, intrinsic costs, and the CPU limits — must share one physical
anchor.

## Recommended calibration

1. **Pin the point↔time anchor.** Keep the fine unit (forced by per-op metering)
   and state it explicitly: ~37,900 points/µs on reference hardware, i.e.
   `points ≈ µs × 37,900`. Equivalently, define a `POINTS_PER_US` constant so a
   µs-denominated config translates deterministically.
2. **Set the intrinsic table from the estimator** (this doc's numbers × safety),
   rounded to stable integers. Replace the flat `per_byte = len` with per-family
   coefficients — sha256 ≈ 35/byte, ripemd160 ≈ 275/byte, memcpy ≈ 10/byte — since
   they differ by ~8×.
3. **Reconcile the CPU limits** to the same anchor: genesis
   `max_transaction_cpu_usage` / `max_block_cpu_usage` expressed in points
   (µs × POINTS_PER_US), so a block's budget is a real wall-clock budget and the
   metered limit doubles as a checktime bound (also closes the native-handler
   checktime gap).
4. **Guard against drift.** Re-run the estimator on a wasmer bump or a hashing-lib
   change; a materially different ratio means the pinned table (a consensus value)
   needs a deliberate revision.

Until (1) and (3) are decided, `cost.rs` keeps its provisional hand-picked values
— deliberately conservative *ordering* but wrong *magnitude* — rather than the
measured numbers, which would be correct but unusable under the current limits.

## Caveats / not yet measured

- Anchoring to the current operator table inherits that table's own lack of
  ns-calibration; the safety multiplier absorbs the slack. A full recalibration of
  the operator costs is the deeper follow-up.
- `memcpy` is modelled as alloc + two native copies; the guest-memory view adds a
  little the estimate doesn't capture (covered by safety).
- Database intrinsics (`db_*`) are **not** measured here — they need a stateful
  harness (chainbase + a populated table, worst-case scan layouts). They remain
  flat `DB_OP`, over-charged on the base and un-charged per row scanned; that's the
  next estimator to build.
