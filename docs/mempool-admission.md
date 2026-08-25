# Mempool admission and concurrency

This document describes PulseVM's local transaction-admission policy, mempool
lifetime rules, and the concurrency boundary between RPC ingress and block
execution. It is not consensus-critical: admission only decides whether a node
keeps and relays a transaction. A producer and every validator still execute
the transaction authoritatively before it can affect chain state.

## 1. Goals and non-goals

Admission should reject transactions that are obviously unusable without paying
for a speculative execution-and-revert cycle. In particular, it checks the
transaction's structure, expiration, referenced accounts and permissions,
duplicate status, and signatures.

Admission deliberately does **not** execute action handlers or WASM. An action
can pass admission and later fail because its state-dependent effects are no
longer valid. The block builder drops such a transaction; validation repeats
execution against the candidate block's selected state.

This is a local policy. Two nodes may retain different subsets of valid
transactions without affecting consensus.

## 2. State ownership

```text
RpcService
  mempool: Arc<tokio::RwLock<Mempool>>
  admission_state: Arc<std::sync::RwLock<Option<MempoolAdmissionState>>>

MempoolAdmissionState
  database: Database clone
  chain_id: Id

Database clone
  ChainDatabase: Arc<Mutex<Db>>
```

The admission state is installed after controller initialization. It is a small
handle: cloning it does **not** copy chain state. `Database` clones share the
same live in-memory arena as the controller. The arena is persisted by the
database layer for node restart, but neither the mempool nor admission state is
a durable transaction queue.

The phrase “admission state view” means a read path over that shared database.
It does **not** mean a versioned snapshot, MVCC read transaction, or immutable
copy.

## 3. Admission path

For a new packed transaction, `RpcService::admit_transaction` performs:

1. Take the mempool read lock, reject a known ID, and determine whether expiry
   pruning is necessary.
2. If expiry is due, briefly take the write lock and remove expired entries.
3. Clone the installed `MempoolAdmissionState` and run preflight on Tokio's
   blocking pool. This avoids holding an async runtime worker for signature
   recovery and database reads.
4. Take the mempool write lock, prune if necessary, and atomically perform the
   final ID/capacity check and insertion.

The final insertion is intentionally the deduplication point. Several identical
requests may complete preflight concurrently, but at most one becomes a pool
entry.

If a service has not installed admission state yet, it falls back to the
controller read lock. That fallback is safe but has the original contention
behavior and is measured separately.

## 4. Controller and database lock boundary

Block build and block verification must retain the controller's exclusive lock:
they mutate controller fields, the live database, and the arena undo stack.
Admission does not take that lock once the state handle is installed.

```text
Block build / verify                         Admission
--------------------                         ---------
Controller write lock                        no controller lock
  mutate pending state                         clone Database handle
  manage undo sessions                         read DB for preflight
  execute actions                              insert into mempool
```

The shared arena has its own mutex. Individual database calls from either path
serialize on that mutex, so this design removes controller-lock queueing, not
all state contention. The mutex protects memory safety; it does not make the
series of reads in one admission atomic.

### Live-state semantics

A preflight may observe mutations belonging to a speculative pending block. For
example, it may see an account created in a pending block that is later
rejected. In that case a transaction referring to that account can enter the
mempool but later fail authoritative execution and be dropped. The converse is
also possible: a preflight may reject a transaction based on a live state that
subsequently changes.

This behavior is safe because admission is advisory. It must not be treated as
an inclusion guarantee or as a transactionally coherent state read.

Obtaining both concurrency and coherent reads requires a larger design:
versioned database snapshots/MVCC, or a separate producer execution pipeline
with an explicitly published state version.

## 5. Detached block batches

`build_block` and `verify_block` detach the live mempool before their expensive
execution phase. The detached `MempoolBatch` owns the prior queue while the
live pool accepts incoming transactions.

The live pool retains reservations for every detached transaction ID. A
reservation:

- counts toward the 10,000-transaction capacity;
- rejects re-gossip of an in-flight ID; and
- prevents newly admitted transactions from displacing deferred transactions
  when the batch is merged back.

On batch completion, reservations are released and transactions the controller
deferred are prepended ahead of transactions admitted during execution. The
original expiry deadline is retained; merging never extends a transaction's
local lifetime.

## 6. Expiry and capacity policy

The mempool hard cap is 10,000 transactions. An entry's effective local expiry
is the earlier of:

- its signed transaction expiration; and
- first-seen time plus the five-minute local TTL.

This bounds memory use even when a sender supplies an excessively long signed
expiration. Expiry is checked on admission, by the block timer, and while
building a block. It is local policy and does not alter a transaction's signed
expiration or consensus validity.

## 7. Observability and validation

`AdmissionMetrics` records state-backed versus fallback preflights and aggregate
and maximum waits for the controller fallback and mempool locks. These metrics
are currently in-process counters; they are not yet exported through a metrics
endpoint.

The test suite covers:

- TTL pruning, capacity, reservations, and merge order;
- ingress during the actual build and verification handoff;
- exactly-once handling of concurrent duplicate submissions; and
- a five-node tmpnet soak that sends 128 signed requests with 32 concurrent
  clients and verifies every admitted transaction is eventually applied.

The soak records request latency, but it is not a hardware-independent
throughput claim. It includes local HTTP, MetalGo-to-VM transport, JSON-RPC,
signature recovery, database reads, and scheduling.

## 8. Current limitations and follow-up work

- The database mutex remains a contention point during execution.
- Admission preflight has no atomic snapshot and can see speculative state.
- Admission metrics need export and a database-mutex wait metric before they
  can provide complete production lock attribution.
- A longer release-build load test, with before/after baselines and multiple
  ingress nodes, is needed before making sustained-throughput claims.
