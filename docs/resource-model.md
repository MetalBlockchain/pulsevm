# PulseVM Resource Model

Status: Draft
Scope: CPU, NET, and RAM accounting for transactions executed by PulseVM

---

## 1. Overview

PulseVM bills three resources, following the Antelope model:

| Resource | Unit | Nature | Reclaimed |
|---|---|---|---|
| CPU | ops (metered WASM points) | Rate-limited over a rolling window | Automatically, as the window advances |
| NET | bytes | Rate-limited over a rolling window | Automatically, as the window advances |
| RAM | bytes | Persistent allocation | Only when the owning object is deleted |

CPU and NET are *flow* resources: an account has a per-window budget proportional to its stake, consumed by transactions and replenished by the passage of time. RAM is a *stock* resource: it is allocated on object creation and returned on deletion, with no time-based recovery.

The critical divergence from Antelope is CPU. Antelope bills CPU in **microseconds of wall-clock execution time**, which is non-deterministic and therefore requires `billed_cpu_time_us` to be carried in the block and validated subjectively against a tolerance. PulseVM bills CPU in **deterministic metered ops**, derived from the executed WASM instruction stream. See §3.4 for why this matters.

---

## 2. Transaction classes

PulseVM distinguishes two transaction classes, which are billed differently.

### 2.1 Input transactions

User-signed transactions arriving via RPC or gossip. Fully billed for all three resources.

### 2.2 Implicit transactions

System-generated transactions produced by the chain itself (e.g. the per-block `onblock`). These are not signed, are not present in the transaction gossip, and do not have an independent payer in the usual sense.

Implicit transactions are billed a flat **100 ops** of CPU and nothing further:

- No WASM metering charge beyond the base
- **No NET charge at all** — an implicit transaction has no packed representation transmitted over the network, so charging for size would be meaningless
- RAM is still charged normally, because implicit transactions genuinely mutate state

This mirrors Antelope's `init_for_implicit_trx(0)`, which passes zero initial NET usage and skips the packed-size accounting entirely.

> **Note:** if an implicit transaction's WASM body were ever to exceed what 100 ops buys, it would trap. The flat charge is a billing decision, not an execution budget. The execution budget for implicit transactions should be set separately and generously, since a failing `onblock` invalidates the block.

---

## 3. CPU

### 3.1 Formula

```
cpu_ops = BASE_OPS
        + (ACTION_OPS × action_count)
        + Σ cost(op) for every WASM operator executed
```

| Constant | Value | Notes |
|---|---|---|
| `BASE_OPS` | 100 | Minimum charge for any transaction |
| `ACTION_OPS` | 100 | Per action in the transaction |

The 100-op floor mirrors Antelope's `min_transaction_cpu_usage = 100`, keeping the constant recognisable even though the unit has changed from microseconds to ops.

`action_count` should be defined explicitly as **actions dispatched**, not actions declared in the transaction body — i.e. inline actions generated during execution each add `ACTION_OPS`. Otherwise a contract can fan out arbitrarily many inline actions while paying the dispatch overhead only once.

Implicit transactions short-circuit to `cpu_ops = BASE_OPS`.

### 3.2 Cost function

Metering is applied via the Wasmer `Metering` middleware with the following cost function:

```rust
const COST_FUNCTION: fn(&Operator) -> u64 = |operator: &Operator| -> u64 {
    match operator {
        Operator::Drop => 2,
        Operator::Select => 3,
        Operator::Br { .. }
        | Operator::BrTable { .. }
        | Operator::Call { .. }
        | Operator::CallIndirect { .. }
        | Operator::Return { .. } => 2,
        Operator::BrIf { .. } => 3,
        Operator::GlobalGet { .. }
        | Operator::GlobalSet { .. }
        | Operator::LocalGet { .. }
        | Operator::LocalSet { .. } => 3,
        Operator::I32Mul { .. }
        | Operator::I64Mul { .. }
        | Operator::F32Mul { .. }
        | Operator::F64Mul { .. } => 3,
        Operator::I32DivS { .. }
        | Operator::I32DivU { .. }
        | Operator::I32RemS { .. }
        | Operator::I32RemU { .. }
        | Operator::I64DivS { .. }
        | Operator::I64DivU { .. }
        | Operator::I64RemS { .. }
        | Operator::I64RemU { .. } => 80,
        Operator::I32Clz { .. } | Operator::I64Clz { .. } => 105,
        Operator::MemoryCopy { .. } | Operator::MemoryFill { .. } => 500,
        Operator::MemoryGrow { .. } => 1000,
        _ => 1,
    }
};
```

Summarised:

| Class | Operators | Cost |
|---|---|---|
| Memory growth | `memory.grow` | 1000 |
| Bulk memory | `memory.copy`, `memory.fill` | 500 |
| Count leading zeros | `i32.clz`, `i64.clz` | 105 |
| Integer division / remainder | `i{32,64}.{div,rem}_{s,u}` | 80 |
| Conditional branch | `br_if` | 3 |
| Locals / globals | `{local,global}.{get,set}` | 3 |
| Multiplication | `{i32,i64,f32,f64}.mul` | 3 |
| Select | `select` | 3 |
| Unconditional control flow | `br`, `br_table`, `call`, `call_indirect`, `return` | 2 |
| Drop | `drop` | 2 |
| Everything else | loads, stores, consts, add/sub, comparisons, conversions, … | 1 |

### 3.3 Metering mechanics

The middleware rewrites the module at compile time, injecting a points decrement at the head of each basic block covering the summed cost of that block's operators. Consequences:

1. **Metering is part of the compiled artifact.** Any cached compilation must be keyed on both the code hash *and* a cost-function version identifier.
2. **Changing the cost function is consensus-breaking.** It must be gated behind a protocol feature, and activation must invalidate every cached module. A node that replays history with a newer cost function will compute different CPU usage and diverge.
3. **Exhaustion traps.** When remaining points hit zero the middleware traps; this surfaces as a CPU-exceeded failure and must be classified as an objective transaction failure (analogous to `tx_cpu_usage_exceeded`), not a subjective one.
4. **Actual consumption is read post-execution** via the remaining-points value, and is the difference between the initial budget and the remainder — including for trapping executions, where the remainder is zero.

### 3.4 Why deterministic metering matters

Because ops are a pure function of the executed instruction stream, every node computes identical CPU usage for identical execution. This removes an entire class of Antelope complexity:

- No `billed_cpu_time_us` field needs to be trusted from the block header
- No leeway/tolerance window when validating a producer's billing claim
- No divergence between a fast producer and a slow validator
- Replay produces byte-identical resource accounting

The tradeoff is that op counts only loosely correlate with real execution time. The cost function is the sole lever aligning billing with actual hardware cost, which makes its calibration a security property rather than a tuning detail. See §6.

### 3.5 Rate limiting

Account CPU budgets follow the Antelope elastic model, with units changed to ops:

- Each account has a per-window CPU budget proportional to `cpu_weight / total_cpu_weight`
- The window is a rolling 24 hours, tracked by an exponential moving average accumulator
- Block-level virtual capacity expands and contracts elastically based on recent block fullness, bounded by `maximum_elastic_resource_multiplier`
- Greylisting clamps the multiplier to 1 for the affected account on speculative blocks only

The following configuration values need to be redenominated from microseconds to ops before launch:

| Parameter | Antelope default (µs) | PulseVM (ops) |
|---|---|---|
| `max_block_cpu_usage` | 200,000 | TBD |
| `max_transaction_cpu_usage` | 150,000 | TBD |
| `min_transaction_cpu_usage` | 100 | 100 |

The ratio between `max_transaction_cpu_usage` and `min_transaction_cpu_usage` sets the maximum spam amplification factor and should be chosen deliberately rather than carried over by analogy.

---

## 4. NET

### 4.1 Formula

NET is charged on the serialized size of the transaction as it appears on the wire, decomposed into prunable and unprunable portions:

```
unprunable_size = packed_size(transaction) + FIXED_NET_OVERHEAD_OF_PACKED_TRX
prunable_size   = packed_size(signatures) + packed_size(context_free_data)

discounted_prunable = ceil(prunable_size × CF_DISCOUNT_NUM / CF_DISCOUNT_DEN)

initial_net_usage = BASE_PER_TRANSACTION_NET_USAGE
                  + unprunable_size
                  + discounted_prunable
```

At finalization the accumulated usage is rounded up to an 8-byte boundary:

```
net_usage = (net_usage + 7) & ~7ULL
```

The 8-byte quantum is not incidental — it is the unit of the transaction header's `max_net_usage_words` field, so NET usage and the self-imposed cap are expressed in the same granularity.

| Constant | Antelope reference value | Purpose |
|---|---|---|
| `BASE_PER_TRANSACTION_NET_USAGE` | 12 | Flat per-transaction overhead |
| `FIXED_NET_OVERHEAD_OF_PACKED_TRX` | 16 | Packed-envelope overhead |
| `CF_DISCOUNT_NUM / CF_DISCOUNT_DEN` | 20 / 100 | Discount on prunable data |
| `TRANSACTION_ID_NET_USAGE` | 32 | Only relevant to deferred transactions |

> Confirm these against the PulseVM chain config before relying on them; they are carried from Antelope's `chain/config.hpp` and may have been retuned.

The prunable discount exists because signatures and context-free data can be discarded once a block is irreversible, so they impose less long-term storage cost on the network than the transaction body.

Deferred transactions are out of scope; if they are not implemented, the `delay_sec > 0` surcharge path does not apply.

### 4.2 Limit resolution

The effective NET limit for a transaction is the minimum of several sources, and *which* source binds determines how a failure is classified:

1. Remaining block NET capacity → `net_limit_due_to_block = true`
2. `max_transaction_net_usage` from chain config
3. Minimum available NET across all billed accounts → clears the block flag, may set the greylist flag
4. The transaction header's `max_net_usage_words × 8`, if non-zero and not greater than the current limit → clears the block flag

The header limit can only tighten, never loosen. When it applies, the transaction has opted into its own ceiling, so an overrun is attributable to the transaction rather than to network conditions.

Failure classification:

| Binding source | Exception | Retryable |
|---|---|---|
| Block capacity | `block_net_usage_exceeded` | Yes — subjective, may fit a later block |
| Greylisted account | `greylist_net_usage_exceeded` | Yes — subjective, node-local policy |
| Transaction header or account limit | `tx_net_usage_exceeded` | No — objective |

Greylisting must remain subjective. It is node-local configuration, not consensus state, so a greylist-induced failure must never be recorded as an objective rejection — two nodes with different greylists would otherwise disagree about validity.

### 4.3 Implicit transactions

Not charged. `initial_net_usage = 0`.

---

## 5. RAM

### 5.1 Model

RAM is charged as a signed delta against a payer's persistent allocation, applied whenever a billable object is created, resized, or removed:

```
delta = new_billable_size - old_billable_size
add_pending_ram_usage(payer, delta)
```

| Operation | Delta |
|---|---|
| Create object | `+billable_size(object)` |
| Modify object, same payload size | `0` |
| Modify object, payload grows/shrinks | `±(new_payload - old_payload)` |
| Remove object | `-billable_size(object)` |
| Change payer | `-size` from old payer, `+size` to new payer |

The billable size of a row is not the payload size alone. It includes fixed struct overhead plus per-index overhead:

```
billable_size(row) = struct_overhead
                   + payload_bytes
                   + (OVERHEAD_PER_ROW_PER_INDEX × index_count)
```

| Constant | Antelope reference value |
|---|---|
| `OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES` | 32 |
| `OVERHEAD_PER_ACCOUNT_RAM_BYTES` | 2048 |
| `SETCODE_RAM_BYTES_MULTIPLIER` | 10 |

> The per-object-type billable sizes should be pinned against the actual PulseVM struct definitions rather than copied from Antelope, since the storage layout differs.

### 5.2 Lifecycle details worth specifying explicitly

- **Table objects.** The table metadata object is created when the first row is inserted into a (code, scope, table) triple and destroyed when the last row is removed. The payer for the table object is the payer of the row that triggered creation, which is not necessarily the payer of the row that triggers deletion. The accounting must handle the asymmetry — the refund goes to whoever is recorded as the table's payer, not to the deleting account.
- **Secondary indices.** Each secondary index row is separately billable and carries its own per-index overhead.
- **Contract code.** `setcode` charges the code size multiplied by `SETCODE_RAM_BYTES_MULTIPLIER`, reflecting that compiled artifacts and validation structures cost substantially more than the raw bytes.
- **New accounts.** Account creation charges `OVERHEAD_PER_ACCOUNT_RAM_BYTES` plus the account object itself.
- **Verification is at commit.** RAM sufficiency is checked once at the end of the transaction against the accumulated pending delta, not incrementally per object. A transaction may transiently exceed its quota provided the net position at commit is within limits.
- **Rollback releases nothing.** On transaction failure the entire state change is reverted, including RAM deltas. RAM is never "consumed" by a failed transaction — but CPU and NET are, which is what prevents free spam.

### 5.3 No rate limiting

Unlike CPU and NET, RAM has no time-based replenishment and no elastic virtual limit. An account either has sufficient unallocated RAM or it does not. There is consequently no greylist interaction and no block-level RAM budget.

---

## 6. Cost function review items

The following are observations about the current cost function that should be resolved before mainnet. They are listed in rough order of severity.

### 6.1 Bulk memory operations are billed as constant-time

`memory.copy` and `memory.fill` are charged a flat 500 regardless of length. Both are O(n) in the byte count. A single `memory.fill` over a 1 MiB region costs the same as filling one byte.

This is the most exploitable gap in the model: a contract can perform hundreds of megabytes of memory traffic for a few thousand ops. The charge should be length-proportional. Since the length is a runtime stack value rather than an immediate, the middleware cannot see it — this needs a host-side charge, either by lowering bulk-memory ops to metered host calls or by injecting an explicit charge before the operation.

The same applies to `memory.grow`, where the flat 1000 is independent of the number of pages requested.

### 6.2 Host functions are effectively unmetered

The cost function meters WASM operators only. A call into a host intrinsic costs `Call = 2` plus nothing else, regardless of the work performed on the host side. Database intrinsics, cryptographic intrinsics, and serialization helpers all fall into this hole.

A loop calling a moderately expensive intrinsic is currently the cheapest way to do a large amount of real work. Every host function needs an explicit ops charge applied from within the host implementation, and that charge needs to be calibrated against measured cost rather than assigned by intuition.

### 6.3 `clz` is priced above integer division

`i32.clz` / `i64.clz` cost 105; `i32.div_s` and friends cost 80. On real hardware this is inverted — `LZCNT` is a 3-cycle instruction, integer division is 20–90 cycles depending on operand width. Unless there is a specific reason (a software fallback on the target architecture, for example), the two should be swapped or `clz` should drop to a small constant.

### 6.4 Bit-counting operators are inconsistent

`clz` is priced at 105 but `ctz` and `popcnt` fall through to the default of 1, for all widths. Whatever the correct price for this class, the three should be consistent. This looks like an oversight rather than a deliberate choice.

### 6.5 Floating-point division is unpriced

`f32.mul` and `f64.mul` are explicitly priced at 3, but `f32.div`, `f64.div`, and `f{32,64}.sqrt` fall through to 1 — despite being the most expensive floating-point operations. If floating point is permitted at all, division and sqrt should be priced in line with their integer counterparts.

More fundamentally: **is native floating point permitted?** Antelope routes float operations through softfloat precisely because native FP risks cross-platform divergence in NaN payload propagation and rounding edge cases. If PulseVM executes floats natively via Wasmer, that is a determinism question that outranks the pricing question. If floats go through softfloat host functions, then §6.2 applies and the operator prices here are dead code.

### 6.6 Memory access is cheaper than local access

All load and store operators (`i32.load`, `i64.store`, etc.) fall through to the default of 1, while `local.get` costs 3. This is backwards: a local read is a register access or a stack slot, whereas a linear-memory access involves a bounds check and a potential cache miss.

Given that loads and stores dominate the instruction mix of most real contracts, this is likely the single largest source of systematic underpricing after §6.1 and §6.2 — not because any individual operation is expensive, but because of sheer frequency.

### 6.7 `call_indirect` is priced identically to `call`

`call_indirect` additionally performs a table bounds check and a runtime type-signature comparison. A modest premium over the direct-call cost is warranted.

### 6.8 Calibration methodology

The values above are individually arguable. The broader point is that the current table appears to have been assigned by hand rather than derived from measurement. Before finalizing:

1. Benchmark each operator class on target validator hardware
2. Fix a reference: e.g. 1 op ≈ 1 ns on a defined baseline machine
3. Derive the table from measurements, rounding to convenient integers
4. Validate against real contract workloads — a token transfer, a DEX order match, a multisig approval — and confirm that measured wall time per op stays within a narrow band across those workloads

The metric that matters is not per-operator accuracy but variance in ops-per-second across realistic workloads. A cost function where the cheapest workload achieves ten times the ops-per-second of the most expensive one gives an attacker a 10× discount on the resource they actually want to exhaust.

---

## 7. Worked examples

### 7.1 Input transaction — single token transfer

Assume: one action, 128-byte packed transaction body, one 66-byte signature, no context-free data, receiver's balance row already exists.

**NET**

```
unprunable_size     = 128 + 16 = 144
prunable_size       = 66
discounted_prunable = ceil(66 × 20 / 100) = 14
initial_net_usage   = 12 + 144 + 14 = 170
net_usage           = (170 + 7) & ~7 = 176 bytes  (22 words)
```

**CPU**

```
base           = 100
actions        = 100 × 1 = 100
wasm metering  = 34,800   (measured)
cpu_ops        = 35,000
```

**RAM**

Both balance rows are modified in place with unchanged payload size, so the delta is 0. Nothing is billed.

If the receiver's row did not exist, the delta would be `billable_size(key_value_object)` — struct overhead plus payload plus per-index overhead — charged to whichever account the contract designated as payer.

### 7.2 Implicit transaction — `onblock`

```
cpu_ops   = 100        (flat)
net_usage = 0          (not billed)
ram       = delta from any state mutation, billed normally
```

---

## 8. Open questions

1. What are the ops-denominated values for `max_block_cpu_usage` and `max_transaction_cpu_usage`?
2. Does `action_count` include inline actions dispatched during execution? (Recommended: yes.)
3. Are context-free actions supported, and do they receive separate CPU accounting?
4. Is native floating point permitted, or are floats routed through softfloat? (§6.5)
5. What is the protocol-feature mechanism for revising the cost function post-launch, and how are cached compiled modules invalidated on activation?
6. Are deferred transactions supported? If not, the `TRANSACTION_ID_NET_USAGE` surcharge and the delayed-transaction NET path can be removed entirely.
7. Is there a subjective CPU/NET billing path for failed transactions, and how does it interact with deterministic op counting?