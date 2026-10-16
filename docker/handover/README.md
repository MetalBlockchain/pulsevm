# Handover rehearsal

Rehearses the shadow-then-promote migration on one machine: a
single-producer Leap chain ("normal XPR") produces blocks, a PulseVM shadow
replays them in real time, the producer halts at `TERMINAL_HEIGHT`, and a
five-node PulseVM network boots from the checkpointed shadow state and
continues numbering at H+1.

```bash
# ~10 minutes at the default 1200 blocks (0.5s block time).
docker/handover/run-handover.sh start
docker/handover/run-handover.sh stop
```

## What it models

| Step | Models |
|---|---|
| Leap produces, shadow follows | Live XPR replay (today's EC2 follower) |
| `stop xpr-producer` at H | The producer halt commitment (all BPs stop) |
| Snapshot, export, checkpoint | Canonical export plus independent validation |
| Source-block anchor | Id-exact empty block H attached to the manifest so new nodes adopt H as tip |
| Five-node boot from checkpoint | A-Chain validator boot from identical state |
| Parent-linkage plus liveness asserts | Continuity gate: H+1 builds on H |

`TERMINAL_HEIGHT` sets the cutover (default 1200; 100000 is ~14 hours).
`HANDOVER_WORK_DIR` must stay below `/tmp` for the nodeos-docker adapter.

## Prerequisites

Host Rust with LLVM 22 (for the checkpoint importer), Docker with the
`pulsevm-handover` compose project, and MetalGo plus the network runner
for the five-node boot (`METALGO_EXEC_PATH`, same defaults as
`scripts/run-local.sh`). No XPR core checkout is needed: preflight and the
deferred sidecar are mainnet provenance guards, and the fixture chain has
no deferred activity, so the rehearsal skips them by design.

## Known delta vs the real migration

Promotion currently re-identifies the chain: the migration genesis commits
to the checkpoint hash, so the five-node network reports a different chain
ID than the Leap chain. The rehearsal asserts state continuity (parent link
H to H+1, advancing head) across that re-identification. Same-ID
in-process promotion — the shadow process itself starting to author at H —
needs block production inside the replay binary and is not modeled here.

Full run: `TERMINAL_HEIGHT=300 ./run-handover.sh start` runs everything
unattended — three-node Leap consensus, shadow follow to N, full network
halt with a freeze proof, checkpoint, five-node boot, the network's own
first transaction (empty blocks are gated, so H+1 needs one), and the
continuity asserts. It ends with `handover: PASS` and leaves the new
network running.

Rehearsal-only support: `XPR_REPLAY_GENESIS_FILE` lets the replay binary
follow a non-mainnet fixture chain. It is default-off; without it every
mainnet pin behaves exactly as before.

Producer schedule: a migration restore starts a new schedule seeded from the
migration genesis initial key (the source schedule is not carried over), so
the boot wires `PULSEVM_GENESIS_INITIAL_KEY` from the fixture genesis the
Leap producer uses. With a foreign key every build fails closed at the
signing gate (`refusing to produce`, now logged by the VM) and the new
network never passes H. The real migration ceremony must write the actual
producers' keys into the migration genesis the same way.
