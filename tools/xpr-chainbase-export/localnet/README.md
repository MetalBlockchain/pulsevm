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
  /tmp/xpr-export/state-history/chain_state_history.log /tmp/pulsevm-xpr-arena
```

The export adapter mounts `/tmp` into the container at the same path, so the
export work directory must be below `/tmp`. Stop the source fixture when done:

```bash
tools/xpr-chainbase-export/localnet/run.sh stop
```

Run the importer against the emitted `chain_state_history.log` once its CLI
bootstrap is available. A successful local fixture only establishes that the
wire-format/export path works; it is deliberately not evidence of compatibility
with an XPR Mainnet snapshot.
