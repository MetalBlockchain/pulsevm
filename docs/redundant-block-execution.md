2# Redundant block execution in the block lifecycle

Status: analysis, grounded in code as of commit `bb573cf0`. No changes made yet.

## Summary

A block's transactions are executed **at least twice on every node**, and under any
consensus depth greater than one, **many more times than that**. All of the redundant
work stems from a single design choice: every speculative execution pass ends by
throwing its result away (`undo()`), so the post-execution state and the transaction
traces are recomputed from the last accepted block on the next call instead of being
retained.

This is the highest-ROI performance target found so far because it is a *reuse/caching*
problem, not an architectural rewrite: the block content is fixed and execution is
deterministic, so a result computed once is valid to reuse verbatim.

## The three execution call sites

`execute_block` (`crates/pulsevm_core/src/chain/controller.rs:492`) runs every
transaction in a block serially. It is reached from three places:

| Entry point | Path | Result |
|---|---|---|
| `build_block` (`:253`) | executes mempool txs, computes merkle roots | `root_session.undo()` — **discarded** (`:354-357`) |
| `verify_block` (`:362`) | `execute_block` (`:401`) | `root_session.undo()` — **discarded** (`:408-411`) |
| `accept_block` (`:416`) | `execute_block` (`:432`) | `root_session.push()` + `db.commit()` — **committed** (`:441-451`) |

`execute_transaction` (`:584`), called per transaction by all three, re-runs the full
per-tx cost each time:
- signature recovery — `recovered_keys()` (`:601`) re-runs ECDSA recovery every call, no
  cache (`transaction/signed_transaction.rs:51`);
- WASM instantiation — a fresh `Store` + ~200-entry `imports!` table + `Instance::new`
  per invocation (`wasm_runtime.rs:240-438`); only the compiled `Module` is cached;
- all fine-grained FFI state operations against chainbase.

## Redundancy factor #1 — per-node double execution (~2×)

On any single node, exactly two of the three call sites run for a given block:

- **Producer** (the node that built the block):
  - `build_block` executes the block, then **undoes** it (`:354-357`).
  - `build_block` inserts the block into `verified_blocks` (`:349-352`), so the
    producer's own `verify_block` early-returns without executing (`:367-368`).
  - `accept_block` executes the block **again** and commits it.
  - → **2× execution** (build discarded, accept committed).

- **Validator** (received the block from a peer):
  - `verify_block` executes the block, then **undoes** it (`:408-411`).
  - `accept_block` executes the block **again** and commits it.
  - → **2× execution** (verify discarded, accept committed).

The committed `accept_block` pass exists only to (a) reproduce the state delta to
`push()`, and (b) reproduce the `transaction_traces` needed by `store_traces` (`:446`).
Both were already computed by the immediately preceding build/verify pass and thrown
away.

## Redundancy factor #2 — replay re-execution (scales with pending window)

Because speculative passes always `undo()`, the database is never left holding the state
of a pending (verified-but-not-yet-accepted) block. To rebuild that state, both
`build_block` and `verify_block` begin with:

```
replay_accepted_state_to(tip, ...)   // controller.rs:283 (build), :399 (verify)
```

`replay_accepted_state_to` (`:836`) walks from the target back to
`last_accepted_block_id` and calls `execute_block` on **every** block in between
(`:862-869`). `last_accepted_block_id` only advances in `accept_block` (`:450`), so any
block that consensus has verified but not yet finalized sits in this replay path.

Let **K** = number of verified-but-unaccepted blocks between `last_accepted` and the tip
(the consensus pending-window depth). Then, per new tip block:

- each `build_block` re-executes those K ancestors, then the new block → **K + 1**
  block-executions;
- each `verify_block` on a validator does the same → **K + 1**;
- `accept_block` normally replays nothing extra, because blocks are accepted in order so
  `parent_block_id == last_accepted_block_id` and the replay path is empty (`:430`), then
  executes the one target block → **1**.

So the amortized execution multiplier is roughly **(K + 2)×** versus an ideal **1×**:
`2×` in the degenerate case where finalization keeps exact pace with production (K = 0),
and higher — potentially quadratic total work across a run of K pending blocks — as the
window grows. The true K is a runtime property of the Avalanche polling depth and should
be measured (see "What to measure").

## Root cause

All three redundancies are the same bug wearing different hats:

> Speculative execution state and traces are always discarded (`undo`) and recomputed
> from `last_accepted`, never retained keyed by block id.

`verified_blocks` already caches the *block* to let the producer skip re-verifying its
own block (`:349`, `:367`). The fix extends that existing pattern: cache the *result of
execution* (state delta + traces), not just the block bytes.

## What can be safely reused, and why it's safe

Execution is deterministic — WASM metering canonicalizes NaNs and the LLVM compiler is
configured for determinism (`wasm_runtime.rs:181-221`), transactions are executed in a
fixed order, and there is no wall-clock or nondeterministic input in the execution path.
Therefore a result computed in build/verify is bit-for-bit identical to the one
`accept_block` recomputes. Reuse changes performance, not consensus outcome.

Chainbase's undo model is a stack of sessions (`pulsevm_ffi/src/bridge.rs`,
`database.rs:236`). A session can be **kept open and pushed later** instead of undone,
which is exactly what retention needs.

Three reuse opportunities, in increasing order of care required:

1. **build → accept reuse (producer).** Retain the block's computed state session and
   `transaction_traces` at build time, keyed by block id, instead of `undo()`-ing.
   `accept_block` then `push()`es the retained session and calls `store_traces` with the
   retained traces — no re-execution. Safe as long as the base state at accept matches
   the base at build (same parent; guaranteed for in-order acceptance).
   **Implemented** (see below).

2. **verify → accept reuse (validator).** Identical to #1 but the retained result comes
   from `verify_block` rather than `build_block`. Implemented as part of #1, since both
   feed the same retention slot.

3. **replay avoidance.** Keep pending blocks' state materialized as a stack of retained
   sessions (block id → session) rather than undoing and replaying. Then
   `replay_accepted_state_to(tip)` becomes: if the DB already holds the correct pending
   chain, do nothing; otherwise unwind/replay only the differing suffix. This removes the
   (K+1) amplification and is the largest win, but also the one that most needs correct
   fork-switch handling. **Not yet done.**

## Implementation status (opportunity #1 + #2)

Implemented in `controller.rs` as a **single-slot** retention: `Controller` gains a
`pending: Option<PendingBlock>` holding the live undo session and traces of one block
whose state is materialized on top of `last_accepted_block_id`.

- `build_block` and `verify_block` retain their executed session + traces instead of
  `undo()`-ing, but only when the block builds directly on the last accepted block
  (`preferred_id == last_accepted_block_id` / `parent == last_accepted_block_id`); this
  guarantees the held session contains exactly that one block's mutations. `build_block`
  now also runs `finalize_block_resources` (factored out of `execute_block`) so its
  retained state is identical to what a re-execution would commit.
- `accept_block` takes a fast path when `pending` matches the accepted id and its parent
  is still the last accepted block: it `push()`es the retained session, reuses the
  retained traces, and skips both `replay_accepted_state_to` and the second
  `execute_block`.
- `clear_pending` (undo + restore base) runs at the start of every path that needs the
  plain last-accepted base — `build_block`, `verify_block`, the slow `accept_block`
  branch, and `reject_block` when the rejected block is the pending one. `push_transaction`
  does **not** clear it: its nested undo session auto-undoes on drop (LIFO-safe) and
  leaves the pending session intact.

One behavior change: between a retained build/verify and the matching accept, the live
database holds the pending (not-yet-committed) block's state, so a concurrent read RPC can
observe the about-to-be-accepted tip rather than strictly the last accepted state. This is
head-vs-irreversible read semantics and does not affect consensus state.

## Implementation status (opportunity #3 — replay avoidance)

The single slot was generalized to a **pending chain**: `Controller.pending_chain:
Vec<PendingBlock>`, an ordered stack of executed-but-unaccepted blocks whose sessions are
stacked on the live database (`pending_chain[0].parent == last_accepted`,
`pending_chain[i].parent == pending_chain[i-1].id`).

- `replay_accepted_state_to` no longer re-executes the whole window. It computes the target
  path, keeps the longest prefix already materialized on `pending_chain`, unwinds only the
  divergent tail, and executes only the blocks not yet applied. When the chain already
  matches (building/verifying on the current tip) it is a no-op. This removes the (K+1)
  amplification: an N-block pending window now costs N executions total instead of ~N².
- `build_block` / `verify_block` reconcile to their parent then push their own block onto
  the chain (no longer restricted to `parent == last_accepted`).
- `accept_block` commits the **front** of the chain (chainbase `commit` frees only the
  oldest undo state) and keeps the rest live; the fallback re-executes on the accepted base.
- `reject_block` unwinds the rejected block and every descendant built on it.
- `execute_block` increments a `blocks_executed` counter — the read-only instrumentation the
  "what to measure" section calls for, and what the test below asserts against.

**Critical gotcha (fixed):** the pending sessions form a chainbase LIFO undo stack, so they
must be released tip-first. Letting `Vec<PendingBlock>` drop naturally destroys them
oldest-first, undoing the stack out of order — a **SIGSEGV**. `Controller` has an explicit
`Drop` that pops the chain from the tip. `unwind_pending_to` pops tip-first for the same
reason. Any future code that clears the chain must preserve reverse order.

Covered by `test_build_accept_reuses_pending_state`, `test_reject_discards_pending_state`,
`test_verify_block`, and `test_pending_chain_reuses_executed_prefix` (which builds a
two-block chain and asserts `blocks_executed == 2`, not 3) in `controller.rs`.

**Still open:** fork-switch reconciliation is handled by unwind+replay of the divergent
suffix, but has no dedicated multi-fork test yet; and `accept_block` assumes in-order
acceptance (parent == last accepted), erroring otherwise rather than committing a multi-block
prefix at once.

## Safety caveats to handle in any implementation

- **Fork switches / `set_preference`.** When preference moves to a different fork, the
  retained live state may belong to the wrong branch. The session stack must be
  unwindable so the correct fork can be replayed. Retention must be keyed by block id and
  validated against the current parent before reuse; on mismatch, fall back to
  re-execution (current behavior) rather than trusting a stale session.
- **Block rejection.** `reject_block` (`:471`) must drop any retained session/traces for
  the rejected id (and its descendants) so they are not accidentally pushed later.
- **Memory.** Retained sessions cost memory proportional to the state deltas of the
  pending window (bounded by K). This is the price paid to remove O(K) recomputation;
  bound it by the consensus depth and drop entries on accept/reject.
- **Verification must still run.** Reuse is about not re-*executing* to reproduce state
  and traces; a validator must still have executed the block once (in `verify_block`) to
  validate its merkle roots (`:404`). #2 reuses that pass's output; it does not skip
  verification.

## What to measure before implementing

To size the win and pick the order of the three reuse opportunities:

1. **K, the pending-window depth** — how many blocks sit in `verified_blocks` between
   `last_accepted` and the tip at steady state. This determines whether replay avoidance
   (#3) dominates or the simple build/verify→accept reuse (#1/#2) captures most of it.
2. **Per-pass execution time** — instrument `execute_block` to record wall time and count
   of `execute_transaction` calls per invocation, tagged by `BlockStatus`
   (Building / Verifying / Accepting). This directly shows the multiplier in practice.
3. **Signature-recovery and WASM-instantiation share** of a single `execute_transaction`,
   so we know how much of the redundant pass is crypto vs. VM setup vs. FFI state ops.

Recommended first step: land the instrumentation in #1–#2 above (cheap, read-only), run a
representative load, and confirm the measured multiplier matches the (K + 2)× model
before building retention.
