# Verification of detached forks

A verified block remains a valid candidate parent when another branch is
materialized in the arena. Producer schedules are resolved by following
`verified_blocks` parent links back to the last accepted block. The nearest
schedule change in those authenticated headers supplies the active schedule;
otherwise the accepted schedule applies. Resolution must reach the accepted
tip even when a schedule change is found earlier. Unknown ancestors and
branches that no longer descend from the accepted tip are rejected.

The pending chain is a database execution cache, not the set of known parents.
For example, after verifying A → B and then A → C, a valid child of B must still
verify. The producer signature is checked against B's schedule before replay;
producer-account existence is checked after B's state has been materialized.

## Compatibility and deployment

This fix changes consensus-visible acceptance of valid fork descendants that
older nodes reject depending on arrival order. It requires a **coordinated
upgrade** of all validators before resuming block processing; mixed-version
rolling deployment is not supported. This uses the coordinated-upgrade option
in the repository agent guide. Wire formats, schedule activation semantics and
protocol version 1 remain unchanged; no new height activation is introduced.
See [protocol-features.md](protocol-features.md) for the general rollout policy.

Regression coverage verifies switching back to a detached verified parent,
acceptance of its descendants, removal of losing-branch state, and rejection
of unknown parents and branches below the accepted tip.
