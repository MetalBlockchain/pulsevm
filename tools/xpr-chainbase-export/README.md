# XPR chainbase export

This tool turns an XPR node snapshot into the portable state-history input for
the PulseVM Arena importer. It deliberately does **not** read
`state/shared_memory.bin`: that file is a chainbase mapped-memory image whose
pointers, allocator metadata and ABI depend on the exact XPR binary.

Instead, it starts the matching XPR `nodeos` with its
`state_history_plugin`. XPR core writes a complete chain-state delta for the
first accepted block when the history log is empty. That delta contains the
logical chainbase tables (accounts, code, permissions, resources, contract
tables and rows, and secondary indexes) in the standard SHiP framing. The
PulseVM importer can hydrate Arena from that representation without relying on
chainbase's physical layout.

## Source pin

The source was validated against `XPRNetwork/core` revision
`cbb24506280275f4fb51fb9d77758ff8249fa655`. Build the exporter nodeos from the
same revision that produced the snapshot. Pass a different revision explicitly
with `--source-revision`; it is written into `manifest.env` and checked by the
importer.

## Export

```bash
tools/xpr-chainbase-export/export.sh \
  --nodeos /opt/xpr/bin/nodeos \
  --snapshot /data/xpr/snapshots/snapshot.bin \
  --work-dir /data/xpr-export-123456789 \
  --p2p-peer proton.p2p.example:9876
```

The script refuses an existing output directory and never changes the supplied
snapshot. It stops the temporary XPR node after `chain_state_history.log` has a
record. Give it multiple `--p2p-peer` arguments when a peer might be
unavailable.

## Output contract

`manifest.env` binds the source commit, input snapshot hash and history-log
hash. The future importer treats those values as part of the migration record.
It must reject a log that has no initial full-state block, unsupported table
delta types, modified/removed rows, or fields that cannot be represented by
PulseVM's Arena schema.

The first converter implementation will consume this log into a new Arena
checkpoint, then the five-node e2e harness will boot from that checkpoint with
a fresh PulseVM producer schedule. This is a migration to a new PulseVM chain,
not a continuation of XPR block IDs or signatures.
