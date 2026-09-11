# Consensus-safe optimistic parallel execution

## Goal

Use otherwise idle validator cores to execute independent explicit transactions
in parallel while preserving the exact result of the current serial executor.
Transaction order, receipts, billed resources, traces, Merkle roots, database
state, and failure behavior remain serial-order authoritative. Parallelism is a
node-local optimization and does not introduce a protocol feature.

The serial executor remains the reference implementation and the mandatory
fallback. A speculative result is committed only when a deterministic conflict
check proves that it observed the state it would have observed in serial order.

## Execution boundary

Keep these operations serial:

- block header, timestamp, producer schedule, and protocol-feature validation;
- `eosio::onblock` and other implicit actions;
- due deferred transactions, `onerror`, and deferred retirement;
- transaction receipt ordering and transaction/action Merkle construction;
- final Arena commit, accepted logs, state-history output, and mempool removal.

Initially speculate only explicit packed transactions in their canonical block
order. Inline and context-free actions remain inside their parent transaction
and execute serially on that transaction's worker. A transaction that changes
code, ABI, permissions, resource limits, producer state, or protocol state is
valid input; its recorded writes simply force dependent later transactions to
fall back to serial execution.

## Deterministic algorithm

1. Execute the block's serial prelude and freeze a versioned read view.
2. Assign explicit transactions to workers by transaction index. Completion
   order never affects validation or commit order.
3. Each worker executes against an isolated overlay and produces:
   - the transaction result and action traces;
   - deterministic CPU/NET/RAM billing inputs;
   - an exact key read set and write set;
   - range/index dependencies for lower-bound, upper-bound, and iteration reads;
   - a database changeset that has not touched canonical Arena state.
4. Visit results strictly in receipt order. A result is valid only if none of
   its reads, range dependencies, or writes conflict with earlier committed
   writes. Treat a write as an implicit read unless the database operation is
   proven to be an unconditional blind write.
5. Apply a valid changeset and its trace in order. Re-execute a conflicting,
   incomplete, or failed speculative result with the existing serial executor
   on the current canonical prefix, then commit that serial result.
6. Run the existing semantic root checks and block accept path unchanged.

Conflict decisions use only transaction order, recorded dependencies, and
versioned state. They never depend on wall-clock timing, worker identity, or
which task finishes first.

## Database work

Add the concurrency boundary in `pulsevm_database`, below contract execution:

- `VersionedReadView`: immutable block-prefix snapshot plus per-record versions;
- `TransactionOverlay`: read-through snapshot with private ordered writes;
- `ReadDependency`: exact primary/secondary keys and conservative index ranges;
- `TransactionChangeset`: ordered inserts, updates, removals, and metadata;
- `validate_and_apply`: serial-order conflict validation and atomic Arena apply.

Every consensus database intrinsic must route through the overlay abstraction.
Iterator and range reads require phantom protection: until interval tracking is
proven, any write to a table/index read through iteration conflicts. Resource
limits, permissions, generated transactions, code/ABI, protocol features, and
producer schedules are versioned records, not untracked side channels.

Arena itself remains single-writer. Worker overlays must not open concurrent
Arena undo sessions or mutate shared iterator caches. The first implementation
should favor conservative conflicts over unsafe parallel commits.

## Failure and resource semantics

- Metered WASM points are deterministic and stay local to each overlay.
- Subjective wall-clock deadlines are not committed state. Queue delay must not
  turn an otherwise valid block into a consensus rejection.
- A speculative exception is authoritative only when its dependency set still
  validates; otherwise the transaction is re-executed serially.
- RAM quota checks and deferred scheduling are evaluated against the ordered
  prefix. Stale speculative decisions conflict and re-execute.
- A worker panic, incomplete dependency record, unsupported intrinsic, or
  overlay limit always degrades to serial execution for that transaction.

## Rollout gates

1. **Dependency telemetry:** instrument the serial executor, measure read/write
   set sizes and expected conflict rates, and do not change execution.
2. **Shadow mode:** execute selected transactions in overlays but commit only the
   serial result; compare status, billing, traces, changesets, and roots.
3. **Validator mode:** enable ordered optimistic commit with sampled serial
   replay comparison and an automatic process-level serial escape hatch.
4. **Producer mode:** enable only after validator parity over the full XPR replay
   and sustained multi-node tests.

### Current dependency-telemetry slice

The first rollout gate is available behind the node-local
`PULSEVM_DEPENDENCY_TELEMETRY` environment variable. It is unset by default and
does not change transaction execution or Arena state. When enabled, each
explicit/deferred serial transaction receives an isolated recorder through its
cloned `Database` handle; inline actions and WASM host functions inherit that
same recorder. Debug logs include the transaction id, outcome, counts, exact
contract/system keys, conservative range keys, and writes.

The recorder covers the contract primary table plus idx64, idx128,
idx256, idx_double, and idx_long_double. Point reads use stable logical row keys
and iterator/secondary searches conservatively depend on the whole relevant
index, including absent reads. Table existence and payer reads track the table
metadata row. Child creation/removal also writes that metadata because it
changes the table row count and can create or delete the table.

Consensus-visible system state reached by explicit/deferred transaction
execution is also recorded: accounts and metadata, code objects, permissions,
permission usage and links, chain configuration, proposed producer schedules,
protocol features and their preactivation queue, resource limits/usage/config,
input-transaction dedupe rows, deferred transactions, and receipt sequence
counters. Permission-tree walks and due-deferred scans use conservative range
keys. Exact logical keys deliberately coarsen pending/committed resource limits
and singleton state where field-level merging has not been proven safe.

Serial telemetry reports still intentionally set `complete = false`, so they
cannot authorize an optimistic commit. They measure working sets but do not run
through the typed overlay described below, and an independent call-path audit
must still prove future execution cannot bypass either dependency recording or
private writes. Global action receipt sequencing and per-block resource usage
are conservative singleton writes, so they currently conflict across
transactions; safe ordered rebasing or aggregation is required before telemetry
can translate into useful parallel commits.

### Contract-primary overlay foundation

The database now also exposes a default-off, typed speculation wave for the
first bounded overlay slice. Starting a wave mutably borrows the controller's
canonical `Database`, freezing that handle while workers receive cloneable
read-only snapshots. Because Arena does not yet provide MVCC or copy-on-write
snapshots, the snapshot shares the frozen store and carries both the Arena
revision and a lazily installed logical-mutation epoch. Reads check the epoch
before and after touching Arena; any write through an instrumented alias makes
the snapshot stale and prevents commit. Nodes that never start a wave do not
install the atomic epoch and retain the normal write path.

Worker overlays currently expose only exact contract-primary get/create/update/
remove operations. Writes remain private ordered logical operations keyed by
`(code, scope, table, primary)`; they never contain Arena object ids or blob
references. Ordered apply validates snapshot version, completeness, and prior
writes, then invokes the live logical database API inside a nested undo session,
so Arena assigns ids in canonical transaction/operation order. Secondary
indices, range iteration, and every system-state operation are unsupported in
this slice and must mark the worker result incomplete for serial re-execution.
After any serial fallback, the conservative implementation invalidates the
remaining wave rather than letting results from the old prefix commit.

This API is not wired into block execution. Before that integration, every
transaction database mutation must be routed through the typed overlay, the
mutation-epoch bypass audit must cover lifecycle/state-replacement methods, and
global receipt/resource singletons need an ordered rebase strategy. An Arena
MVCC/COW read view would eventually replace the controller freeze invariant,
but a full state clone per block is explicitly not an acceptable substitute.

Required gates include unit tests for exact keys and range phantoms, inline
actions, authorization changes, contract upgrades, RAM exhaustion, deferred
creation/cancellation, soft/hard failures, and traps; randomized serial-vs-
parallel differential tests; the 512-position parity gate; the complete XPR
history replay; state/trace/Merkle comparison; crash recovery; and a live
five-node network with mixed serial and parallel validators.

## Expected performance

Empty blocks remain dominated by serial `onblock`, so audited WASM instance
reuse is the relevant optimization there. Optimistic execution targets later
busy blocks. Its ceiling is the number of independent explicit transactions per
block, not the machine's raw core count. Measure speedup, conflict rate, serial
fallback rate, overlay bytes, and ordered-commit wait time independently; do not
promote the path unless end-to-end replay improves without any parity delta.
