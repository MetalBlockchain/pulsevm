# Reusing block verification

A block ID hashes its header, not the supplied producer signature or block body.
The header's Merkle roots authenticate a body only after it has been checked.
Therefore an ID match in the verified-block cache or accepted block log is not
sufficient to skip verification of newly supplied bytes.

Both shortcuts compare the complete header, transaction receipts (including
packed transactions and their signatures), and block extensions with the
previously validated block. These values must match before execution or
transaction authorization can be skipped. A differing producer signature is
recovered against the same header digest and must identify the original,
already-authenticated producer key. This allows alternative valid signatures
without making acceptance depend on which signature arrived first, and works
for historical blocks after the active producer schedule has changed.

The accepted-log shortcut populates the cache with the canonical block from
disk. A rejected candidate never replaces cached data, mutates chain state,
or creates a pending arena session. Exact duplicates retain the fast path.

## Compatibility and deployment

The change closes a validation bypass for malformed blocks sharing a valid
header. Valid block wire formats, IDs, receipts and execution are unchanged.
Because older nodes can incorrectly report the malformed representations as
valid depending on their cache, this correction requires a **coordinated
upgrade** of validators under the repository agent guide's upgrade exception.
It does not add a height activation or change protocol version 1. Follow the
rollout policy in [protocol-features.md](protocol-features.md).

Tests cover memory, accepted-log and reopened-database shortcuts, altered
transaction bodies, removed signatures, changed resource receipts, block
extensions and invalid producer signatures. They also cover exact round-trip
duplicates and different valid producer signatures over the same header.
