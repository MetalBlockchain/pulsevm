# XPR chainbase export

This tool turns an XPR node snapshot into the portable state-history input for
the PulseVM Arena importer. It deliberately does **not** read
`state/shared_memory.bin`: that file is a chainbase mapped-memory image whose
pointers, allocator metadata and ABI depend on the exact XPR binary.

Instead, it starts the matching XPR `nodeos` with its
`state_history_plugin`. XPR's Leap nodeos writes a complete chain-state delta for the
restored snapshot head when the history log is empty. That delta contains the
logical chainbase tables (accounts, code, permissions, resources, contract
tables and rows, and secondary indexes) in the standard SHiP framing. The
PulseVM importer can hydrate Arena from that representation without relying on
chainbase's physical layout.

## Source pin

XPR Network Mainnet uses [Antelope Leap 5.0.3](https://github.com/AntelopeIO/leap/releases/tag/v5.0.3).
The exporter source is pinned to its `d133c6413ce8ce2e96096a0513ec25b4a8dbe837`
release commit. Build the exporter nodeos from the
same revision that produced the snapshot. Pass a different revision explicitly
with `--source-revision`; it is written into `manifest.env`. For Mainnet, run
the read-only preflight against the exact source checkout and trusted snapshot
provenance before starting nodeos:

```bash
tools/xpr-chainbase-export/preflight.sh \
  --nodeos /opt/xpr/bin/nodeos \
  --snapshot /data/xpr/snapshots/snapshot.bin \
  --xpr-core /src/antelope-leap \
  --require-sidecar-plugin \
  --minimum-free-gib 250
```

Preflight verifies the checkout's exact Git commit, snapshot digest, disk
space, optional peer syntax, and installation/linkage of the required source-side
plugin. It cannot infer a snapshot's producing revision from the binary file;
that mapping must come from the snapshot publisher or operator who created it.

## Export

```bash
tools/xpr-chainbase-export/export.sh \
  --nodeos /opt/xpr/bin/nodeos \
  --snapshot /data/xpr/snapshots/snapshot.bin \
  --work-dir /data/xpr-export-123456789 \
  --chain-state-db-size-mb 4096
```

The script refuses an existing output directory and never changes the supplied
snapshot. It stops the temporary XPR node only after Leap logs that its initial
state record is complete. Leave `--p2p-peer` unset for a snapshot-only export:
this prevents post-snapshot blocks from changing the history log before its
manifest is hashed.

For a bounded replay corpus, keep one or more archive peers and request a
window after the snapshot head. The exporter records the snapshot height,
target height, and observed head in `manifest.env`:

```bash
tools/xpr-chainbase-export/export.sh \
  --nodeos /opt/xpr/bin/nodeos \
  --snapshot /data/xpr/snapshots/snapshot-at-H-minus-10000.bin \
  --work-dir /data/xpr-export-window \
  --p2p-peer archive.example.org:9876 \
  --post-snapshot-blocks 10000
```

This captures the state-history stream while the source node catches up to at
least the requested target. The current Arena importer still hydrates the
initial full-state record only; consuming the later delta records as a
consensus replay window is a separate step. A window therefore supplements,
but does not replace, the base snapshot.

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
the **same restored snapshot head** as `chain_state_history.log`. Do not use an RPC
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
Arena. Startup re-parses every deferred raw transaction and checks its ID
against the sidecar before allowing the scheduler to run it; an incompatible
XPR transaction therefore fails before the network begins producing blocks.
Once a record's delay has elapsed, it executes outside the mempool without
re-checking its original signatures. If it is already expired, PulseVM retires
it with XPR's ID-only `expired` receipt. Otherwise, if execution fails,
PulseVM invokes `eosio::onerror` on the source sender with XPR's
`onerror(sender_id, sent_trx)` ABI payload; a successful callback produces an
ID-only `soft_fail` receipt and retires the record. Successful deferred
execution also uses an ID-only receipt. Producer and validator both replay
these paths from the committed Arena record.

`deferred-sidecar-plugin/` contains the exact-XPR-source plugin that writes
this file from chainbase during plugin startup, after snapshot hydration and
before P2P catch-up. Install it in
a clean checkout at the pinned revision and rebuild nodeos:

```bash
tools/xpr-chainbase-export/install-deferred-sidecar-plugin.sh \
  --xpr-core /src/XPRNetwork-core
# rebuild /src/XPRNetwork-core/programs/nodeos/nodeos using the normal XPR build
```

Then request it during state-history export:

```bash
tools/xpr-chainbase-export/export.sh \
  --nodeos /src/antelope-leap/build/programs/nodeos/nodeos \
  --xpr-core /src/antelope-leap \
  --snapshot /data/xpr/snapshots/snapshot.bin \
  --work-dir /data/xpr-export-123456789 \
  --chain-state-db-size-mb 4096 \
  --deferred-sidecar /data/xpr-export-123456789/deferred-transactions.json
```

Large Mainnet snapshots can exceed nodeos's default chainbase allocation. Pass
`--chain-state-db-size-mb` (for example `4096`) when the source node reports
that the database lacks storage for the snapshot. The allocation must fit the
machine running nodeos.

The installer refuses a non-pinned Git checkout and never overwrites an
existing plugin. The exporter also refuses to proceed if a requested sidecar
was not produced. This makes a missing rebuild or an incorrect plugin
registration visible before the Arena conversion begins.

The first converter implementation will consume this log into a new Arena
checkpoint, then the five-node e2e harness will boot from that checkpoint with
a fresh PulseVM producer schedule. This is a migration to a new PulseVM chain,
not a continuation of XPR block IDs or signatures.
