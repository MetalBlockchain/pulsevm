# XPR → A-Chain Handover Rehearsal: Proof Record

Status: proven on EC2 (2026-10-16), twice — clean run and chaos run.
Branch: `feat/handover-rehearsal`. Companion design doc:
[xpr-achain-migration.md](xpr-achain-migration.md); validator
commitment strategy: [halt ceremony](xpr-halt-ceremony.md).

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

## Rehearsal-harness lessons (Oct 2026 local runs)

- `start` drops the compose volumes first, so every rehearsal halts a FRESH
  chain. Before this, reruns silently resumed the previous run's chain from
  its named volume: traffic/boundary account creation then collided with
  already-existing accounts and the terminal height was already passed.
  (The earlier H=330 PASS is still a valid cutover proof for that chain,
  but it was not a fresh-chain run; the H=328 PASS below is.)
- `leap_send` fails loud (curl errors, retries, rejection bodies) instead of
  masking failures inside a pipefail pipeline, where a duplicate or rejected
  transaction used to kill the run via a bare `set -e` exit with no
  diagnosis. Boundary submits and `leap_chain_head` reads retry transient
  failures for the same reason.
- `chain_rpc_url` uses the runner's own `--dial-timeout`/`--request-timeout`
  instead of GNU `timeout`, which does not exist on macOS: with the wrapper,
  discovery silently returned empty on Mac hosts and every boot died with
  "new network RPC never came up" while the five-node network underneath
  was healthy (consensus running, tip == H).
- The five-node supervisor detaches with a python double-fork + `setsid(2)`
  (with `os.set_inheritable` on std fds — CLOEXEC would otherwise break the
  exec'd supervisor's stdout) so the network survives its launcher; a bare
  `nohup ... &` stays in the launcher's process group and dies with it.
- `cmd_boot` fails fast when the runner port is already bound (three spaced
  probes), instead of burning the whole RPC wait on a squatted port.
- Record: fresh-chain v2 rehearsal (`HALT_V2=1`) PASS — halt commitment over
  H=328, five-node restore with tip 328 == H and head id equal to the
  committed halt block, H+1=329 parent-linked, state equivalence 4/4, boundary
  traffic 10/10 exactly-once.

## What this does NOT prove (do not merge as migration-complete)

- Promotion re-identifies the chain; same-ID in-process promotion is unmodeled.
- The halt ceremony here is single-key. The restore gate now supports a
  weighted 2/3 roster quorum and checkpoint-bound version 2 commitments
  (see [halt ceremony](xpr-halt-ceremony.md)), but a live rehearsal with
  distinct per-validator keys, a voted schedule, and a signed roster
  distribution path is still unproven.
- CEX freeze/re-enable, gateway cutover, and Hyperion reindex runbooks live
  in the migration design doc, not in this rehearsal.
- Resuming boot into the same workdir overwrites the plugin binary and kills
  the previously booted network. Treat one workdir as one live network.
- Fixture keys (`5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3`) are
  disposable rehearsal-only secrets, never mainnet keys.
