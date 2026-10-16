# XPR → A-Chain Handover Rehearsal: Proof Record

Status: proven on EC2 (2026-10-16), twice — clean run and chaos run.
Branch: `feat/handover-rehearsal`. Companion design doc:
`docs/xpr-achain-migration.md` (on `docs/xpr-achain-migration`).

## What was proven

A live shadow-then-promote swap: a 3-node XPR (Leap) network runs to a
terminal height, commits to halt, truly freezes; a 5-node PulseVM network
restores the checkpoint, verifies the halt commitment, authors H+1, and
stops the replay. From the customer's seat the network never stops — it
swaps, with every boundary transaction landing exactly once.

Latest proven run (EC2 `ubuntu@52.30.206.93`, `TERMINAL_HEIGHT=300`):

- XPR consensus (1 producer + 2 validators) → halt at **H=310**,
  id `00000136d50d237759274fb59b5822472e5cb5834e081ce82e3d64405982bf46`.
- Signed halt commitment over H into the migration manifest; new network
  verifies schedule membership before restoring (tampered commitments fail
  closed — covered by `migration_restore_accepts/rejects_*` unit tests).
- Replay stopped explicitly once the shadow absorbed H.
- Block **311 builds on the halt block** (parent link asserted on all nodes).
- State equivalence **4/4** (`eosio,t1,t2,t3`) via payload-compared authorities.
- Boundary audit **10/10 txs exactly-once** (5 pre-halt on old chain, 5 post-halt
  on new chain; none lost, none duplicated).
- Chaos trial (`CHAOS_KILL_NODE=1`): H+1 finalized on 4/5 quorum — same PASS.

## Reproduce

```sh
git checkout feat/handover-rehearsal
./docker/handover/run-handover.sh stop
LEAP_HTTP_PORT=18880 SHADOW_RPC_PORT=19660 \
  ./docker/handover/run-handover.sh start > /tmp/handover.log 2>&1
# expect: "handover: PASS: block ... builds on committed halt block ..."
```

Port remaps are required on hosts running live XPR infra (`:8888` relay,
`:9660` follower). Resume a halted run from its checkpoint without replaying:

```sh
HANDOVER_WORK_DIR=<archived-workdir> ./docker/handover/run-handover.sh resume-boot
```

Ops detail (traffic seeding, snapshot flow, chaos mode): [handover README](../docker/handover/README.md).

## What this does NOT prove (do not merge as migration-complete)

- Promotion re-identifies the chain; same-ID in-process promotion is unmodeled.
- The halt ceremony here is single-key. Real cutover needs distinct
  per-validator keys, a voted schedule, a 2/3 weight threshold, and a signed
  artifact distribution path — format-compatible (no manifest change), but
  the ceremony itself is undefined.
- CEX freeze/re-enable, gateway cutover, and Hyperion reindex runbooks live
  in the migration design doc, not in this rehearsal.
- Resuming boot into the same workdir overwrites the plugin binary and kills
  the previously booted network. Treat one workdir as one live network.
- Fixture keys (`5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3`) are
  disposable rehearsal-only secrets, never mainnet keys.
