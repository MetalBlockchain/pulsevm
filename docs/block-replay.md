# Block replay and producer schedules

Every call to `Controller::execute_block` resolves the producer schedule from
that block's parent before executing `onblock` or any input transaction. This
includes first-time verification, trusted replay of verified blocks, and
fallback acceptance after speculative state has been unwound.

`block_active_schedule` is execution context, not durable state. It must never
be inherited from the last execution: that execution may belong to a descendant
or a different fork. A state-summary request can also clear all pending arena
sessions without changing the last execution's context. Contracts must observe
the same active producers and proposed-schedule version on every execution of
the same block, including the schedule-changing block itself (which uses its
parent's schedule) and its child (which uses the newly proposed schedule).

## Compatibility and deployment

This correction is consensus-relevant: older binaries can replay a valid block
into different producer permissions depending on prior speculative execution.
The fix preserves wire layouts, resource prices and protocol version 1, but is
an unconditional correction requiring a **coordinated upgrade** of all
validators before resuming block processing. Do not deploy it as an ordinary
mixed-version rolling upgrade. This is the coordinated-upgrade alternative
allowed by the repository agent guide; no height activation is added here.

Replaying affected history with the old behavior is not deterministic across
nodes, so a height gate cannot reliably reconstruct that behavior. Before
resuming, agree on a last accepted state and compare canonical state roots;
nodes with divergent accepted state must be rebuilt from that agreed state.
Installing this fix does not repair previously committed incorrect permissions.
See [protocol-features.md](protocol-features.md) for the general upgrade policy.

The regression exercises a real WASM schedule proposal, independent block
verification, a state-summary unwind, multi-block trusted replay and fallback
acceptance. It compares producer permissions, canonical state roots, persisted
block bytes and state after database reload on both sides of the schedule change.
