# Local XPR fixture

This harness runs an isolated, single-producer XPR-compatible Leap 5.0.3 node
in Docker. It is intended to validate the XPR-to-Arena conversion plumbing;
it does not connect to XPR Mainnet and therefore does not reproduce Mainnet
state.

```bash
tools/xpr-chainbase-export/localnet/run.sh start
snapshot=$(tools/xpr-chainbase-export/localnet/run.sh snapshot)
tools/xpr-chainbase-export/export.sh \
  --nodeos tools/xpr-chainbase-export/localnet/nodeos-docker \
  --snapshot "$snapshot" \
  --work-dir /tmp/xpr-export \
  --p2p-peer xpr-producer:9876 \
  --source-revision leap-5.0.3

cargo run -p pulsevm_database --example xpr_import_check -- \
  /tmp/xpr-export/state-history/chain_state_history.log \
  /tmp/pulsevm-xpr-arena \
  /tmp/pulsevm-xpr-migration.snapshot
```

The export adapter mounts `/tmp` into the container at the same path, so the
export work directory must be below `/tmp`. Stop the source fixture when done:

```bash
tools/xpr-chainbase-export/localnet/run.sh stop
```

The optional final importer argument emits an Arena migration checkpoint. Make
the same checkpoint file available to every Pulse node, then include it in each
node's VM configuration:

```json
{
  "migration_checkpoint": "/shared/pulsevm-xpr-migration.snapshot"
}
```

The controller restores it before normal Arena genesis authoring, so all nodes
begin from identical imported state. The runner still needs an explicit way to
mount this file and inject the per-node VM configuration; that integration is
the next step. A successful local fixture establishes only the export and
conversion path; it is deliberately not evidence of compatibility with an XPR
Mainnet snapshot.
