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

The optional final importer argument emits an Arena migration checkpoint and a
same-named `.manifest.json` file that commits to its bytes, revision, source
block ID, and source state-history log. Start the five-node Pulse harness with
that checkpoint:

```bash
METALGO_EXEC_PATH=../metalgo/build/metalgo \
METAL_NETWORK_RUNNER_PATH=../metal-network-runner/bin/metal-network-runner \
PULSEVM_MIGRATION_CHECKPOINT=/tmp/pulsevm-xpr-migration.snapshot \
scripts/run-local.sh
```

The harness injects `migration_checkpoint` into the runner's chain config and
the controller restores it before normal Arena genesis authoring, so every node
begins from identical imported state. It derives a migration-specific target
genesis from the manifest checkpoint hash. A successful local fixture establishes
the export, conversion, and five-node boot path; it is deliberately not evidence
of compatibility with an XPR Mainnet snapshot.
