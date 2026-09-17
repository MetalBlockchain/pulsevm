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

A shared coordinator token serializes wave and batch ownership across cloned
database handles. A low-level wave holds it for its complete lifetime, while a
batch holds it across fallback-driven wave restarts and shadow rollback/replay;
a competing clone fails before opening an Arena session.

Worker overlays expose exact contract-primary and secondary-index
get/create/update/remove operations. All five secondary families use canonical
raw values: idx64, idx128, idx256, double bits, and long-double word pairs.
Writes remain private ordered logical operations keyed by
`(code, scope, table, index, primary)`; they never contain Arena object ids or
blob references. Ordered apply validates snapshot version, completeness, and
prior writes, then invokes the live logical database API inside a nested undo
session, so Arena assigns ids in canonical transaction/operation order.

Adapters can record a conservative whole-index range dependency before a
lower/upper-bound or iterator observation. Any earlier insert, removal, or
secondary re-key in that index then forces serial replay, including absent-read
phantoms. Producing iterator results from the private overlay and every
system-state operation remain unsupported in this slice and must mark the
worker result incomplete for serial re-execution. After any serial fallback,
the conservative implementation invalidates the remaining wave rather than
letting results from the old prefix commit.

### Bounded ordered executor

`Database::execute_speculative_batch` turns the contract-primary overlay into a
usable default-off executor for callers that can express a unit of work as a
`SpeculativeTask`. It uses at most the caller-supplied non-zero worker count,
stores results by canonical task index, and visits them only in that order.
Worker completion order is therefore unobservable.

Each worker result contains its private changeset and output. The coordinator
publishes that output only after ordered conflict validation and atomic Arena
apply succeed. A worker error, panic, incomplete dependency set, apply failure,
or dependency conflict discards the speculative output and invokes the task's
authoritative serial implementation in a normal per-transaction undo session.
It then starts a new snapshot and re-speculates the uncommitted suffix; no result
from the stale wave can commit. The entire batch has an enclosing undo session,
so an error from the serial implementation restores the pre-batch state.
An unexpected canonical mutation through an aliased database handle is treated
more strictly: the coordinator aborts and rolls back the whole batch rather than
executing serially on a contaminated prefix.

Repeated suffix invalidation is bounded. After two restarted waves, the
coordinator stops speculating and executes the remaining suffix serially. This
node-local escape hatch preserves canonical order and results while preventing
a hot key or consistently unsupported task from causing quadratic
re-execution.

The executor deliberately mirrors the controller's block/per-transaction undo
nesting. This is required even for logically equivalent primary-row updates:
Arena's blob-span reuse depends on session boundaries and is included in its
state fingerprint. Differential tests compare ordered outputs and full Arena
state roots against the serial reference across a deterministic conflict-heavy
workload. Additional tests cover actual simultaneous workers, fallback/restart,
worker errors and panics, and whole-batch rollback.

`Database::execute_speculative_shadow_batch` provides the matching shadow gate
for the same task surface. It runs and fingerprints the optimistic batch inside
an undo session, restores the exact starting state, and then runs the serial
implementation authoritatively. The returned report compares ordered outputs
and Arena state roots while the database always retains the serial result, even
when parity fails.

The bounded executor is not yet wired into general block execution. It is safe
for its closed exact contract-row task surface, while an arbitrary WASM
transaction still reaches secondary indexes and system state outside that
overlay. Before controller integration, every transaction database mutation
must be routed through the typed overlay, the mutation-epoch bypass audit must
cover lifecycle/state-replacement methods, and global receipt/resource
singletons need an ordered rebase strategy. An Arena MVCC/COW read view would
eventually replace the controller freeze invariant, but a full state clone per
block is explicitly not an acceptable substitute.

Required gates include unit tests for exact keys and range phantoms, inline
actions, authorization changes, contract upgrades, RAM exhaustion, deferred
creation/cancellation, soft/hard failures, and traps; randomized serial-vs-
parallel differential tests; the 512-position parity gate; the complete XPR
history replay; state/trace/Merkle comparison; crash recovery; and a live
five-node network with mixed serial and parallel validators.

## Microbenchmarks

The database crate includes a Criterion benchmark for 64 deterministic,
CPU-bound tasks under three dependency shapes: independent rows, a 25% hot-key
mix, and one fully contended hot key. Each scenario compares the serial
reference with one, two, four, and eight optimistic workers:

```sh
cargo bench -p pulsevm_database --bench optimistic_execution --locked
```

Use `-- --quick` for a smoke sample. Criterion reports elements per second and
the timed path consumes the coordinator's outputs, outcomes, wave count, and
state root. The independent case measures useful parallelism; the mixed and
hot-key cases guard fallback and serial-escape behavior. These are database
coordinator microbenchmarks, not end-to-end WASM or node-throughput claims.

## Expected performance

Empty blocks remain dominated by serial `onblock`, so audited WASM instance
reuse is the relevant optimization there. Optimistic execution targets later
busy blocks. Its ceiling is the number of independent explicit transactions per
block, not the machine's raw core count. Measure speedup, conflict rate, serial
fallback rate, overlay bytes, and ordered-commit wait time independently; do not
promote the path unless end-to-end replay improves without any parity delta.
