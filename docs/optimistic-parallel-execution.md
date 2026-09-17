# Consensus-safe optimistic parallel execution

## Goal and status

PulseVM executes independent explicit transactions concurrently while preserving
the exact result of canonical serial execution. Transaction order, authority
checks, deterministic CPU/NET/RAM billing, receipts, action digests, Merkle
roots, Arena state, and failure behavior remain serial-order authoritative.

The production path is enabled by default on hosts with at least two usable
workers. It is used both while producing a block from the mempool and while
validating or replaying a block. Parallelism is node-local: nodes may choose
different worker counts without changing block validity or state.

## Serial boundary

These operations remain serial:

- block headers, timestamps, schedules, and protocol-feature activation;
- `pulse::onblock` and other implicit actions;
- due deferred transactions, retirement, and `onerror`;
- ordered speculative commit or serial fallback;
- transaction/action Merkle construction and end-of-block accounting;
- accepted logs, state-history output, and mempool removal.

Only explicit packed transactions are sent to workers. Inline and notification
actions execute normally inside their parent transaction. Offline XPR batched
replay remains on its specialized serial/native path because its private native
row cache is not part of the worker snapshot.

## Execution algorithm

1. Execute the serial block prelude and materialize one immutable Arena
   snapshot of that exact prefix.
2. Bound the worker pool by the configured limit, available CPUs, transaction
   count, and the snapshot memory budget.
3. Each worker loads the snapshot once and reuses its private Arena for multiple
   transactions. Every transaction runs in a child undo session and is undone
   before the worker accepts another task.
4. A worker runs the normal signature/authority checks, `TransactionContext`,
   native/WASM dispatch, deterministic metering, resource checks, trace
   construction, and database dependency recording.
5. Successful supported mutations produce a logical execution journal. The
   journal contains stable keys and values, never Arena row IDs, blob offsets,
   or allocator state.
6. The controller visits results strictly in canonical transaction order. A
   candidate may commit only when its exact reads, conservative range reads,
   and non-rebaseable writes do not intersect earlier writes.
7. The controller replays an accepted journal through the ordinary database
   APIs inside a child undo session. Arena therefore allocates physical rows and
   blobs in canonical order. Receipt sequence counters are allocated during
   replay and their action digests are recomputed.
8. A conflict, incomplete journal, worker error or panic, stale resource check,
   or replay error discards that candidate and executes the transaction with
   the existing serial path on the current prefix.

Worker completion order is never observed. A panic recreates the affected
worker fork; it cannot modify canonical state or invalidate a block.

## Dependencies and phantom protection

Dependency keys cover contract primary rows and all five secondary-index
families (`idx64`, `idx128`, `idx256`, `idx_double`, and `idx_long_double`).
Point lookups use stable logical row keys. Bounds, iteration, and absent reads
also record conservative whole-index ranges, so an earlier insert, remove, or
secondary re-key cannot create an unobserved phantom.

System keys cover accounts, code, ABI, permissions and links, permission usage,
chain configuration, producer schedules, protocol features, resource limits
and usage, input-transaction deduplication, deferred transactions, and action
sequence counters. Most system mutations conflict conservatively.

Only fields that have an explicit ordered replay rule are exempt from ordinary
write/write conflicts:

- global action sequence;
- per-account receiver/authorization sequence;
- block resource accumulator state.

Account metadata changes, permission usage, account resource usage, and
transaction dedupe rows are not broadly exempt. This distinction prevents a
contract upgrade or authority/resource mutation from being mistaken for a
harmless counter rebase.

## Logical journal completeness

The authoritative journal currently supports:

- primary and secondary contract-row create, update, and remove;
- account CPU/NET usage and RAM deltas/checks;
- permission last-used updates;
- input-transaction dedupe records;
- action receiver/global/authorization sequence allocation.

At worker completion, PulseVM independently derives the write set explained by
those operations and requires exact equality with the database recorder's
observed write set. A native action such as `newaccount`, `setcode`, `setabi`,
authority mutation, producer proposal, deferred-transaction mutation, protocol
activation, or any future unjournaled write therefore cannot be committed
optimistically; it falls back to serial execution.

This closed-write check is deliberately conservative. Adding a new mutating
database API requires dependency-write instrumentation. Without a journal
representation its observed write makes the candidate fall back to serial;
omitting dependency instrumentation is a consensus-correctness bug and is
called out as an invariant beside the database recorder.

## Ordered resource and receipt semantics

Workers perform deterministic metering and initial quota checks against the
shared prefix. Journal replay then applies CPU/NET usage, RAM deltas, permission
usage, and dedupe writes against the real ordered prefix. If an earlier
transaction exhausted a limit or otherwise invalidated the speculative result,
replay fails atomically and the transaction is re-executed serially.

Global, receiver, and authorization sequences necessarily differ between
workers that started from one prefix. Replay allocates the canonical values,
patches every action receipt, and recomputes the action receipt digests before
Merkle construction. Real token-WASM parity tests compare those digests,
transaction receipts, traces (excluding wall-clock trace telemetry), and the
complete Arena state root against serial execution.

Producer workers also receive the current node-local subjective failure bill.
If a serial fallback fails and changes that non-consensus ledger, all remaining
producer candidates are discarded and the suffix runs serially.

## Resource bounds and configuration

`PULSEVM_PARALLEL_EXECUTION_WORKERS` controls the maximum worker count:

- unset: use `available_parallelism()`, capped at 64;
- `0`: disable full-transaction parallel execution;
- positive integer: use at most that many workers, capped at 64.

`PULSEVM_PARALLEL_EXECUTION_MEMORY_MB` bounds materialized worker Arenas. The
default is 1024 MiB and the accepted maximum is 65536 MiB. The controller uses
a conservative estimate of four times the serialized Arena snapshot per
worker. It also caps workers by available CPUs and task count. Production block
execution requires at least two effective workers; otherwise it uses the serial
path without changing behavior.

One snapshot is serialized per batch and deserialized once per worker, rather
than once per transaction. A future copy-on-write Arena could reduce memory and
startup cost further without changing the journal or ordered-commit protocol.

## Failure and consensus properties

- The canonical Arena remains single-writer.
- Every journal replay is enclosed by a child undo session and is squashed or
  undone exactly once.
- Worker Arenas never share iterator caches or mutable storage with canonical
  execution.
- Subjective wall-clock deadlines are disabled for first-time block validation;
  queueing and host speed cannot decide validity.
- Authorization and deterministic receipt measurement are still required for a
  peer block. Only an exact block already validated by this node may use trusted
  replay mode.
- Parallel settings, task scheduling, completion timing, and log counters are
  node-local and do not enter hashes or state.
- Physical Arena deltas remain a diagnostic/test API only. Authoritative
  full-transaction commit uses logical journals because physical allocator
  offsets from a common prefix cannot be safely merged in general.

## Telemetry

The controller logs worker success/failure counts, complete journals, estimated
dependency waves, elapsed worker time, optimistic commits, and serial fallbacks.
It keeps node-local cumulative commit/fallback counters for tests and future
metrics export.

`PULSEVM_DEPENDENCY_TELEMETRY` emits full serial dependency reports.
`PULSEVM_PARALLEL_WAVE_TELEMETRY` emits conflict-wave estimates. Both are
observational and do not change consensus behavior.

The lower-level `Database::execute_speculative_batch` API remains available for
typed contract-row workloads. It uses the same conservative dependency model,
bounded restarts, ordered apply, serial escape hatch, and whole-batch rollback.

## Verification

The regression suite includes:

- exact point/range keys and secondary-index phantom conflicts;
- concurrent typed tasks, hot-key restarts, worker errors/panics, and rollback;
- reusable full transaction workers that cannot mutate canonical state;
- unsupported native/system writes that deterministically fall back;
- real deployed token-WASM journal replay versus serial receipts, action
  digests, traces, and Arena roots;
- two independent real-WASM transactions that both commit optimistically;
- producer and validator execution of the same conflict-heavy block, with one
  optimistic commit, one serial fallback, and identical final state.

Before release, run the workspace/all-target gates and the frozen replay corpus.
Multi-node E2E remains required when the pinned MetalGo binary and replay
fixtures are available.

## Benchmarks

The database coordinator microbenchmark runs independent, 25%-hot, and fully
contended workloads with one, two, four, and eight workers:

```sh
cargo bench -p pulsevm_database --bench optimistic_execution --locked
```

The core benchmark runs complete deployed-token WASM transactions. It includes
an isolated hot-key speculation measurement plus the production ordered path
for both hot-key and independent-row batches. The ordered measurement includes
snapshot/fork construction, authorization, WASM, dependency capture, conflict
validation, journal replay or serial fallback, and rollback so every sample
starts from the same state:

```sh
cargo bench -p pulsevm_core --bench transfer --locked -- wasm_parallel_execution
```

Use `-- --quick` for a smoke sample. The returned benchmark result exposes
transaction/action counts and optimistic-commit/fallback counts, ensuring the
timed path is consumed. Independent rows show useful scaling; the hot-key case
guards fallback cost and prevents optimistic throughput claims from hiding
contention.

## Performance model

Parallel execution targets busy blocks. Empty or tiny blocks remain dominated
by serial prelude and snapshot overhead and automatically stay serial when
fewer than two workers are useful. The speedup ceiling is the number of
independent explicit transactions, not the host's raw core count. Production
monitoring should track end-to-end block time, snapshot bytes, effective worker
count, optimistic commit rate, fallback rate, and ordered replay time together.
