# Reentrancy and the `has_ancestor` intrinsic

How contract code can be re-entered under PulseVM's action execution model, and
the `has_ancestor` host intrinsic contracts use to guard against it.

## 1. Execution model

There is no synchronous cross-contract call. `send_inline` and
`require_recipient` only *schedule* work (`ApplyContext::execute_inline`,
`ApplyContext::require_recipient`). `ApplyContext::exec` then runs, in order:

1. the action's own WASM, to completion;
2. every notified receiver, one at a time;
3. the queued context-free inline actions, then the inline actions — each
   through `TransactionContext::execute_action`, which runs that action's whole
   subtree before returning.

So no foreign code ever runs while a contract's WASM is on the stack, and the
Ethereum pattern of a callee observing half-updated caller state cannot occur.

## 2. The remaining hazard

Step 3 is depth-first. If `victim::withdraw` queues `A1` (a transfer that
notifies the attacker) and then `A2` (its own bookkeeping), anything the
attacker queues from its notification handler runs inside `A1`'s subtree —
**before** `A2`:

```
victim::withdraw
  ├─ A1  token::transfer → attacker notified → inline victim::withdraw   ← re-entry
  └─ A2  victim::finalize                                                 ← runs later
```

Contracts that defer state updates to a later inline action are re-entrant in
this window. The first defence is checks-effects-interactions: write all state
in the action body before scheduling anything.

## 3. `has_ancestor`

```c
// 1 if an action strictly above the current one in its creator chain has
// receiver `receiver` and, unless `action` is 0, action name `action`.
int32_t has_ancestor(uint64_t receiver, uint64_t action);
```

Every action trace records `creator_action_ordinal`: the action whose execution
scheduled it. For an inline action that is the sender; for a notification it is
the action that called `require_recipient`. The intrinsic follows those links
from the current action to the top-level action
(`TransactionContext::find_ancestor`).

An ancestor is therefore an action whose own WASM has returned but whose
subtree is still running — exactly the re-entry window above. A guard is one
line:

```c
check(!has_ancestor(get_self(), "withdraw"_n), "reentrant call");
```

Semantics:

- The current action is never its own ancestor.
- Notification traces match on the *notified* receiver and carry the original
  action's name, so `has_ancestor(get_self(), "transfer"_n)` also detects
  re-entry while the contract is still handling a `transfer` notification.
- `action == 0` matches any action of `receiver`. Scope the guard by name when
  the contract legitimately inline-calls itself (e.g. a `finalize` step).
- Separate top-level actions of one transaction never interleave, so they are
  never each other's ancestors. Deferred transactions start a fresh chain.
- Unavailable in context-free actions, like `get_sender`.

Regression tests: `has_ancestor_detects_reentry_through_inline_callback` and
`has_ancestor_detects_reentry_through_notification` in `controller.rs` run the
attack above unguarded (re-entry observed) and guarded (transaction aborts).

## 4. Cost

`cost::BASE` plus `cost::ancestor_walk(levels)` = 5 points per ancestor
visited. The walk is bounded by the transaction's action-trace count, which is
itself paid for, and requires strictly decreasing creator ordinals so a corrupt
link fails instead of looping. These values are consensus constants pinned in
`cost::tests::costs_are_pinned`; see
[intrinsic-cost-model.md](./intrinsic-cost-model.md).

## 5. Consensus and compatibility

**Coordinated upgrade.** `has_ancestor` is *not* gated by a protocol feature.
Before it exists, a contract importing it fails at instantiation; after, the
same action succeeds. Nodes running binaries on either side of the change would
disagree about any block containing such an action, so every validator must
upgrade before a contract that imports `has_ancestor` is deployed. If that
cannot be coordinated, gate it behind a feature as `get_sender` is
(`GET_SENDER_FEATURE_DIGEST`); see [protocol-features.md](./protocol-features.md).

**Antelope divergence.** This is a PulseVM-only intrinsic. Contracts that
import it will not run on other Antelope chains.
