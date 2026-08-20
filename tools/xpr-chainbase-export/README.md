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

## Deferred-transaction sidecar

SHiP's `generated_transaction_v0` rows are not a complete chainbase export:
they omit `delay_until`, `expiration`, and `published`. A migration with even
one deferred transaction therefore needs a source-node sidecar captured from
the **same accepted block** as `chain_state_history.log`. Do not use an RPC
query from a later head block: it can produce a plausible but inconsistent
snapshot.

The source-side plugin/tool must write `deferred-transactions.json` in this
lossless format (all numeric XPR names are their underlying `uint64` values;
times are `time_point` microseconds):

```json
{
  "version": 1,
  "source_block_id": "<64 lowercase hexadecimal characters>",
  "transactions": [
    {
      "sender": 6138663591592764928,
      "sender_id": "340282366920938463463374607431768211455",
      "payer": 6138663591592764928,
      "trx_id": "<64 lowercase hexadecimal characters>",
      "delay_until": 1710000000000000,
      "expiration": 1710003600000000,
      "published": 1709999900000000,
      "packed_trx": "<lowercase hexadecimal packed_transaction bytes>"
    }
  ]
}
```

Pass it as the fourth optional argument to the importer:

```bash
cargo run -p pulsevm_database --example xpr_import_check -- \
  /data/xpr-export/chain_state_history.log /data/pulsevm-arena \
  /data/xpr-migration.snapshot /data/xpr-export/deferred-transactions.json
```

The importer verifies the block ID and an exact one-for-one match of every
SHiP identity/payload before it accepts the sidecar. Its checksum is committed
to the resulting migration manifest and the complete records are persisted in
Arena. A node still refuses to boot a migration checkpoint with a nonempty set
until the controller scheduler/executor is enabled; that prevents persisted
records from being mistaken for executable state during the staged rollout.

`deferred-sidecar-plugin/` contains the exact-XPR-source plugin that writes
this file from chainbase on the first `accepted_block` callback. Install it in
a clean checkout at the pinned revision and rebuild nodeos:

```bash
tools/xpr-chainbase-export/install-deferred-sidecar-plugin.sh \
  --xpr-core /src/XPRNetwork-core
# rebuild /src/XPRNetwork-core/programs/nodeos/nodeos using the normal XPR build
```

Then request it during state-history export:

```bash
tools/xpr-chainbase-export/export.sh \
  --nodeos /src/XPRNetwork-core/build/programs/nodeos/nodeos \
  --snapshot /data/xpr/snapshots/snapshot.bin \
  --work-dir /data/xpr-export-123456789 \
  --p2p-peer proton.p2p.example:9876 \
  --deferred-sidecar /data/xpr-export-123456789/deferred-transactions.json
```

The installer refuses a non-pinned Git checkout and never overwrites an
existing plugin. The exporter also refuses to proceed if a requested sidecar
was not produced. This makes a missing rebuild or an incorrect plugin
registration visible before the Arena conversion begins.

The first converter implementation will consume this log into a new Arena
checkpoint, then the five-node e2e harness will boot from that checkpoint with
a fresh PulseVM producer schedule. This is a migration to a new PulseVM chain,
not a continuation of XPR block IDs or signatures.
