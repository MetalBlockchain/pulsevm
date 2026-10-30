# XPR → A-Chain Handover Rehearsal: Proof Record

Status: two-step cutover proven locally (2026-10-21); single-halt proven on
EC2 (2026-10-16), twice — clean run and chaos run.
Branch: `feat/handover-rehearsal`. Companion design doc:
[xpr-achain-migration.md](xpr-achain-migration.md); validator
commitment strategy: [halt ceremony](xpr-halt-ceremony.md).

## What was proven

A live shadow-then-promote swap: a 3-node XPR (Leap) network runs to a
terminal height, commits to halt, truly freezes; a 5-node PulseVM network
restores the checkpoint, verifies the halt commitment, authors H+1, and
stops the replay. From the customer's seat the network never stops — it
swaps, with every boundary transaction landing exactly once.

Latest proven run (EC2 `ubuntu@52.30.206.93`, `TERMINAL_HEIGHT=300`,
two-step memo cutover over the new proof bytes):

- XPR consensus (1 producer + 2 validators) → declared **H=340** at memo
  block 311 (K=29, within max lag 30); confirmation `42978113…dbcb2`
  binds checkpoint + successor chain; offline verifier PASS, flip gate
  opened at H.
- Post-H proof over Leap's true producer digest
  (`sha256(sha256(sha256(header) || blockroot) || schedule_hash)` with the
  blockroot read as the header state's last active node): one staged
  header (H+1=341) recorded with its header state and verified at record
  time; the state's hash is bound by the signature itself (with no staged
  change Leap serves the EMPTY pending schedule, so no hash-to-roster
  comparison is attempted — a wrong pin failed the first run of this
  rehearsal live and was removed).
- Seed helper plants the fixture producers row on `eosio` before H, so
  the export carries the system table and the boot cross-check runs:
  `migration halt roster matches checkpoint schedule: 1 producers` on
  all nodes. A table-less checkpoint fails closed at the same gate
  (proven by the previous run, which refused exactly there).
- Learn-then-bind: first boot ran under a fresh runner id, the gate
  refused the derived platform binding, the ceremony re-ran against the
  boot's actual id, nodes relaunched in place — block **341 builds on
  H** (parent link asserted).
- State equivalence **11/11** via payload-compared authorities.
- Boundary audit **10/10 txs exactly-once** (5 pre-halt on old chain, 5
  post-halt on new chain; none lost, none duplicated).

Earlier proven run (local Mac, `TERMINAL_HEIGHT=150`, two-step cutover):

- XPR consensus (1 producer + 2 validators) → declared **H=187** at head 160
  (K=27, within max lag 30); declaration `adfd985e…09bfcc501f` memo'd
  on-chain in block 160, digest re-decoded from chain.
- Halt confirmation `d6be7207…f480090` binds checkpoint + successor chain
  `dcce9db3…`; offline verifier PASS (manifest v2, checkpoint binding ok,
  declaration inclusion `[160,H-27]`, 1/1 roster quorum, strict schedule
  equality); `verification-pass` marker gates the boot (flip gate).
- Snapshot taken on the running producer at exactly H, bound by id; network
  frozen at P=189 (H+2 stragglers by design, see lessons); block **188
  builds on H** (parent link asserted on all nodes).
- State equivalence **11/11** (`eosio,t1,t2,t3` + 7 memo accounts) via
  payload-compared authorities.
- Boundary audit **10/10 txs exactly-once** (5 pre-halt on old chain, 5
  post-halt on new chain; none lost, none duplicated).

Earlier proven run (EC2 `ubuntu@52.30.206.93`, `TERMINAL_HEIGHT=300`,
single-halt):

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
`:9660` follower). On Apple-silicon Macs, and on any host sharing `:18080`:

```sh
XPR_PLATFORM=linux/arm64 XPR_NODEOS_IMAGE=pulsevm-xpr-handover:local \
  XPR_SHADOW_NATIVE=1 TERMINAL_HEIGHT=150 \
  PULSEVM_RUNNER_PORT=18180 PULSEVM_RUNNER_GATEWAY_PORT=18181 \
  HANDOVER_WORK_DIR=/tmp/pulsevm-handover \
  ./docker/handover/run-handover.sh start
```

Resume a halted run from its checkpoint without replaying:

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
- Record: fresh-chain two-step rehearsal PASS at H=163 after the restore
  gate was tightened (pair mandatory, roster-less commitments rejected,
  declaration timing provable via ceremony or recorded inclusion).
  Declaration at memo block 137 (K=26), confirmation binding checkpoint and
  successor chain verified offline, H+1=164 parent-linked, state equivalence
  11/11, boundary traffic 10/10 exactly-once. Two harness fixes made the
  run possible: the SHiP log read path now flushes buffered appends before
  opening the reader (follow-mode tail reads previously failed as Corrupt),
  and ceremony/attach/verifier tools always rebuild (a stale skipped
  verifier binary once failed the offline check on an encoding the code
  already handled).
- Record: five-node contract-path rehearsal PASS at H=170 (Oct 21, 2026)
  with the platform-bound confirmation. Declaration digest `d0434c...`,
  confirmation `d95376...` binding checkpoint `4f3407...`, source block H,
  and platform chain `UJ4N...` (learn-then-bind: the runner assigns chain
  ids non-deterministically, so the ceremony confirms the boot's actual
  id). Offline verifier PASS with `--platform-chain-id`; gate opened
  (member+key roster match, unanimous schedule version 0, frozen-tally
  2/3 quorum); consensus started at lastAcceptedHeight=170; 5/5 head
  agreement at H+1=171 with parent == H_ID; state equivalence 4/4;
  boundary traffic 10/10 exactly-once. Mid-run the runner issued a second
  chain id (`27L2...`); the gate refused it five times by design before
  the confirmation was re-issued for the live chain — the fail-closed path
  proven live, not just asserted.
- Snapshot-while-running: the exact-H snapshot must be taken on the RUNNING
  producer, before the pause. A paused producer cannot serve
  `create_snapshot`; a data-dir copy races the paused commit (frozen head 207
  in memory, blocks.log still at 206); and this Leap build never completes
  `create_snapshot` on non-producing nodes (2.1 MB `.pending-snapshot` file
  written, HTTP response never sent — observed on two nodes). The pre-pause
  snapshot + post-pause id bind (`SNAP_HID == H_ID`) sidesteps all three.
- P vs H: `create_snapshot` costs ~0.36s of the 0.5s block interval, so the
  pause always lands 1–2 blocks past H. The script records the actual frozen
  head P from the validators (agreement + 2s stability, P-H ≤ 5) and proves
  the snapshot binds H by id. Stragglers H+1..P are ignored by design, exactly
  as post-H XPR blocks are ignored by the A-Chain. On mainnet the BPs halt
  cleanly at H (P == H); the P≠H path is a harness artifact.
- Mac rehearsal needs `XPR_SHADOW_NATIVE=1` (the host-built replay binary is
  Mach-O and cannot exec in the Linux shadow container), `XPR_PLATFORM=linux/arm64`
  (compose `platform`, export adapter, and snapshotter all default to amd64),
  and non-default runner ports when the host is shared
  (`PULSEVM_RUNNER_PORT/PULSEVM_RUNNER_GATEWAY_PORT`).
- `[[ "$(wc -l <file)" == 7 ]]` is always false (`wc` pads with spaces) —
  compare numerically. A dead shadow container spins the follow loop forever,
  so the script now fails fast with the shadow's logs when the container dies
  or its RPC never answers.
- Teardown kills the supervisor's process group plus exactly our runner ports
  (the runner can escape the group via reparenting); never `pkill` by bare
  name on a shared host.

## What this does NOT prove (do not merge as migration-complete)

- Promotion re-identifies the chain; same-ID in-process promotion is unmodeled.
- The two-step cutover ran with a 1-member fixture roster (single key). The
  restore gate enforces a strict 2/3+1 count quorum over the unit-weight
  schedule with mandatory version-2 platform-bound commitments
  (see [halt ceremony](xpr-halt-ceremony.md)), and quorum math is
  unit-tested (`migration.rs`, `xpr_import.rs`), but a live rehearsal with
  distinct per-validator keys, a voted schedule, and a signed roster
  distribution path is still unproven.
- CEX freeze/re-enable, gateway cutover, and Hyperion reindex runbooks live
  in the migration design doc, not in this rehearsal.
- Resuming boot into the same workdir overwrites the plugin binary and kills
  the previously booted network. Treat one workdir as one live network.
- Fixture keys (`5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3`) are
  disposable rehearsal-only secrets, never mainnet keys.
