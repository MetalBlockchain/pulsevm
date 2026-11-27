# Cutover operations: coordination, runbook, post-H audit

Companion to the ceremony design (`docs/xpr-halt-ceremony.md`) and the plan
PDF (`docs/xpr-cutover-plan.pdf`). This is the operator-facing procedure:
what gets published when, what to check at each phase, how a failed round
restarts, and how the new chain is proven healthy after H.

## T-14 coordination checklist

Published through the governance decision that fixes H. Every item has one
named owner; nothing ships "when ready".

| Item | Owner | Notes |
|---|---|---|
| H, K, J (halt height, freeze lead, vote window) | Chain ops | H-K is the freeze, H-J..H the vote window |
| Source chain id (XPR) | Chain ops | Hex, canonical |
| Ceremony contract account + code hash, voter release version | Chain ops | BPs verify the hash before deploying |
| Roster snapshot method (producers table, frozen at H-K) | Chain ops | How the roster file is built, byte-exact |
| Coordinator URLs (params + confirmations) | Chain ops | Or the manual file path; cross-checked against the node either way |
| Successor Antelope signing id (`chain_id`, U-1) | Chain ops | Pin, verify it differs from the validated source XPR id, and publish at T-14; wallets and exchanges can preconfigure it |
| Platform chain id (MetalGo subnet id) | MetalGo team | Assigned after registration at H; bound into every confirmation and exposed separately as `platform_chain_id` |
| Wallet/exchange test vectors (pre-H and post-H) | Wallet + exchange leads | Sign/verify fixtures on both chains before the window |
| Stop window P (agreed stop height, P - H) | Chain ops | Measure the live head-minus-LIB gap at T-14 and set `P - H >= 2 x gap + 12`; a Leap snapshot of H only finalizes once H is irreversible, so a shorter window leaves no snapshot. `--preflight` refuses a short window |
| Voter config per producer (producer name, keys, producer API URL) | Each BP | `--preflight` must print GO before the freeze |
| Schedule readiness: `check-schedule-readiness.py` PASS | Chain ops | Every active producer carries a valid K1 schedule key, weights sane, no pending/proposed rotation; a single bad row dooms init |

## Ceremony runbook

Phases, in order. The voter enforces timing; the operator enforces judgment.

1. **Freeze (H-K).** Chain ops runs `init` on the ceremony contract at H-K.
   Every BP runs `--preflight` until it prints GO: node reachable, source
   chain matches, freeze digest recomputed locally equals the on-chain
   digest, member present, no staged schedule change. Chain ops re-runs
   `check-schedule-readiness.py` at freeze time: a rotation staged after
   T-14 fails the freeze before BPs spend signatures on it. A freeze that
   expires (7-day vote window) or carries the wrong H is re-taken with a
   fresh `init` — re-init while voteless, or any time after expiry.
2. **Vote window (H-J..H).** The voter signs and submits unattended, or the
   operator signs manually (byte-identical). Watch `--status`: `vote`
   should read `on-chain` for every rostered producer. Tally vs 2/3 is
   visible on the contract/ceremony table and the coordinator.
3. **H.** Nobody acts. The chain produces H; the voter observes it. With
   `stop_producer` armed, each producer pauses at the agreed stop P (not
   after delivering its confirmation), from the head alone, so a slow
   ceremony read cannot delay it. The voter signs only once its pause is
   confirmed held, the ceremony shows finalized on-chain (the pause is the
   fleet's pact, which only exists once the declaration has a quorum: a round
   that never reached 15 of 21 does not halt the chain), block P's id has been
   identical for several consecutive polls (P is still reversible, and a
   microfork would split the signers across two ids), and the local node shows
   H+1..P empty (zero transaction
   root in every block); a dirty window refuses to sign and says so in the
   log, because the restore gate would refuse the round anyway. A voter
   restarted after H keeps enforcing the pause even if the finality window
   no longer checks out (it logs a warning instead of exiting). Post-H
   stragglers are expected and ignored — the new
   chain never honors them — but a producer still building minutes past H
   means its voter is down: page it.
4. **Confirm (H..H+J deadline).** The voter signs the confirmation over the
   terminal block id, checkpoint, successor id, and platform id, and
   delivers it. Verify inclusion postdates H.
5. **Boot.** A-Chain nodes boot from the exported manifest. The restore
   gate fails closed on: missing pair, digest mismatch, roster drift,
   schedule version split, weight shortfall, checkpoint mismatch,
   platform mismatch. Any refusal is a stop-and-diagnose, never a retry
   with relaxed checks.

6. **LIVE and CONFIRMED are operator signals.** Publish LIVE only after the
   registered platform id is verified, at least two-thirds of validator stake
   has booted on the pinned signing id, and the validator head has agreed for
   30 consecutive blocks. Keep XPR recovery available during the one-hour
   observation window. Publish CONFIRMED after that hour only if the A-Chain
   remains healthy, the API and history continuity checks pass, and the
   coordinator records the decision. Returning to XPR is safe only before
   user-visible writes on A-Chain; LIVE writes require reconciliation and a
   governance recovery decision even before CONFIRMED. After CONFIRMED, participating XPR
   producers should remove their XPR signing keys from live hosts under the
   key-custody policy. This retires keys for those operators; it cannot prevent
   another party from restarting XPR or producing a fork. PulseVM has no
   protocol-level LIVE or CONFIRMED flag; coordinator identity, publication
   channel, and sign-off owners must be assigned before T-14.

**Superseded round.** If H+1 slips in before the pause (snapshot holds a
head past H), the round is dead: the old declaration stays on-chain as
superseded history and the ceremony restarts at a new H. Never reuse an
H, never confirm a superseded digest, never hand-edit a manifest to fit.

**No-go conditions (any one restarts governance, not the loop):**
schedule change staged mid-window, frozen digest mismatch, coordinator
data disagreeing with the local node, tally short of 2/3 at H, or a
confirmation that will not verify. A failed ceremony is a new governance
decision, not a same-H retry.

## Chain ids and platform ordering (testnet and mainnet)

The pinned Antelope signing id and platform id have different roles.
`get_info.chain_id` and SHiP report the pinned id used by wallets to sign;
`get_info.platform_chain_id` reports the MetalGo subnet id. The latter is a
hash of the CreateChain transaction, whose genesis commits to the checkpoint,
so it still exists only after H and is learned-then-bound by the ceremony:

1. After H: export the checkpoint, build the migration genesis, register the
   chain on the MetalGo subnet. The first boot refuses at the restore gate
   (no confirmation binds this platform id yet) and serves no RPC.
2. Chain ops publishes the registered platform id; each BP confirms against
   it (the coordinator cross-checks the id against the local node).
3. A-Chain nodes restart with the confirmation set and pass the gate.

Plan the confirmation window (H..H+J) to include steps 1-2 end to end, and
do not treat the step-1 refusal as an incident. A refusal for any other
reason is a stop-and-diagnose.

## API and history-only nodes

API gateways and Hyperion/SHiP providers use the same verified migration
bundle as validators: pinned genesis, protocol-upgrade schedule, checkpoint,
and manifest. Start them from that checkpoint; do not join by state sync.
Their node config keeps the canonical initial `producer_name`, sets
`block_production_enabled=false`, omits `producer_key`, and sets
`state_sync_enabled=false`. A Hyperion/SHiP provider also sets
`state_history_enabled=true` and `history_provider=true` before first boot so it records a contiguous
history from H+1. An API-only node may disable history if it serves no SHiP
clients. Compare `get_info.chain_id`, `platform_chain_id`,
`block_production_enabled`, `state_sync_enabled`, and
`state_summary_interval` with the release checklist. Publish the gateway only
after the coordinator declares LIVE and the successor validator head passes the
LIVE gate above.

## Admission lock and edge freeze (ceremony requirement)

Everything between H and the agreed stop P must have an empty
`transaction_mroot`, and nothing in the producer binary keeps it empty:
with P hundreds of blocks past H, ordinary traffic lands in that window and
the restore gate correctly refuses every attempt. The lock is therefore part
of the ceremony, not an optimization, on every producer at H:

1. **Admission lock.** The producer stops admitting new transactions into
   blocks it builds (the fleet agent does this on every producer).
2. **Edge freeze.** The API ingress that accepts transactions is closed, and
   p2p transaction relay is severed, so a transaction submitted anywhere
   cannot reach a producer that has not yet locked.
3. **Proof.** The gate verifies the result, never the procedure: every header
   H+1..P must carry an empty transaction root, hash-link from H, sit in the
   scheduled producer's slot, and end on the block id the quorum signed.

This repository does not implement the lock or the freeze. The rehearsal
harness sends traffic only before H, so a green rehearsal says nothing about
them; the gate's refusal of a non-empty window is covered by unit tests
(`post_chain_rejects_non_empty_blocks`). Treat "lock and freeze confirmed on
all 21 producers" as a go/no-go item before H.

## Abort and resume

A round can die after the freeze: the stop P landed before H became
irreversible (the snapshot of H never finalizes and its
`.pending-snapshot-<H id>` file stays), a producer overshot P, H+1 slipped in
before the pause, or a coordinator went dark. The contract state makes this
sharper than a normal retry: once any vote has landed the freeze is locked
(`init` refuses) until the 7-day vote window expires, and voters keep
retrying a delivery that can never complete.

Written procedure, in order, decided by chain ops and announced on the
governance channel before anyone acts:

1. **Declare the round dead.** Name H and the reason. A dead round is never
   retried with the same H, never confirmed, and no manifest is hand-edited
   to fit.
2. **Stop the voters** on every producer (`systemctl stop`). While a voter
   runs it re-pauses its producer on every poll, so resuming first is futile.
3. **Release the admission lock and edge freeze**, then resume production on
   each producer (`producer/resume`). XPR was only ever paused, never halted:
   it continues from where it stopped, and blocks past P are valid XPR blocks
   that the A-Chain simply never honors.
4. **Discard the round's artifacts.** The pending snapshot, staged post-H
   headers, and any exported checkpoint belong to a superseded H.
5. **Start the next round on a clean slate.** Either wait out the 7-day vote
   window and call `init` again, or deploy the ceremony contract to a fresh
   account (deployments are fresh accounts with empty tables, so this is
   always available and is the faster path when votes already landed). Pick
   a new H, new K, and a new P measured from the live finality lag.
6. **Record it.** The dead round's declaration stays on-chain as superseded
   history; note H, the cause and the new parameters in the ops log.

Prevention is cheaper than abort: the voter now refuses to run when
`P - H < 2 x finality_lag + 12`, so the common cause (a stop inside the
finality lag) cannot start.

## Self-derived checkpoint at boot (agent side)

A validator must never boot from a checkpoint it only received. The node
enforces its half: a migration restore needs the config field
`migration_local_checkpoint_sha256` and refuses to start unless it equals the
migration genesis pin (`migration_checkpoint_sha256`) and the manifest hash.
The agent supplies the value, per validator, from its own work:

1. Schedule a Leap snapshot of the local XPR node at exactly H
   (`schedule_snapshot` works on non-producing nodes) and export its state
   history.
2. Run `xpr_import_check <state-history> <arena-dir> <checkpoint>
   --leap-snapshot <snapshot.bin>` and take the sha256 of the checkpoint it
   writes. Conversion is deterministic, so the fleet lands on one hash (the
   rehearsal converts twice in separate processes and requires identical
   bytes).
3. Put that hash in the node's chain config as
   `migration_local_checkpoint_sha256`, and use the same hash when
   configuring the voter's `confirmation.checkpoint_sha256`.
4. Before the node starts, run `xpr_verify_manifest <manifest> <checkpoint>
   --genesis <genesis>` on the delivered bundle; it fails if the genesis
   pins a different checkpoint.

Do not read the value from the delivered manifest or genesis: that makes the
check circular. If a validator cannot take a snapshot at H, it fetches a
checkpoint from a peer and may only boot after that peer's hash matches a
hash it derived itself or that a quorum of independently deriving BPs
published.

## Ceremony contract authority and the 7-day window

`init` requires the ceremony contract account's own authority
(`require_auth(get_self())`): nobody else can freeze a schedule or re-freeze a
voteless one. Without it anyone could stand up a one-member ceremony, vote
once, and present a finalized singleton; the voter additionally latches
"finalized" only for a singleton whose digest, H and source chain id equal
its own expected declaration, so a foreign ceremony can never arm the pause.
The vote window is 7 days: an `init` after it expires wipes a finalized
ceremony, and a voter restarted later then never arms. Run the freeze (`init`)
within 7 days of P and do not re-`init` after the quorum landed.

A voter that learns of the finalization late (read errors, a restart) pauses
after P. It therefore signs only after scanning H+1 through the head it
actually stopped at, not just through P, so a late pause cannot carry
uncovered traffic into a confirmation. `--print-digest` applies the same
policy as the signing loop (finalized ceremony, pause held, P settled, window
empty) before it prints a confirmation digest.

## A stale schedule pin: abort before H

The published schedule hash (`confirmation.schedule_sha256`, also pinned in the
genesis) includes the schedule
version, and XPR's version moves. The voter checks the live active schedule
against the pin at start and on every poll before H, and in `--preflight`, and
exits with an explicit error if they differ (nothing has been paused before H).
The voter durably records this declaration's abort before returning exit code 3.
The log carries an `ALARM event=cutover.schedule_pin_abort` line and names the
round-specific marker. A restart with the same declaration digest exits 3 again
instead of re-arming it; a new declaration digest has a separate marker path.
If writing the marker fails, keep the voter stopped and page the coordinator
before any restart. There is no on-chain abort, so a bump between
finalization and H splits the fleet (voters that polled in the gap exit; the
rest pause at P and then cannot sign): tell the coordinator out of band the
moment it fires, before P.
Recovery for a stale pin, all before H: read the new hash from any node
(`xpr_snapshot_schedule <current snapshot>` prints it), rebuild the migration
genesis with the new `migration_schedule_sha256` (the ceremony chain id changes
with it), republish the genesis and chain id, and re-run the declaration on a
fresh contract account. After H the schedule is frozen by the window; a pin
mismatch there refuses to sign instead.

The voter's config is checked when it starts. `confirmation.schedule_sha256`
(the published schedule hash) is always required: it is the one pin known
before H. The checkpoint hash, the migration genesis and the platform id only
exist after H (conversion of the H snapshot, then chain creation), so the
ceremony agent starts the voter with `confirmation.operator_fed: true` and no
post-H fields, then restarts it as each one is written. Whatever is present is
validated at load (the genesis must pin the operator's own checkpoint and the
same schedule hash). Without `operator_fed`, a config missing any of the three
refuses to load, so a coordinator-only config still cannot start. The pause
never waits on these fields: once this voter's own declaration is finalized it
pauses at P regardless. Signing needs all three and says "signing blocked"
until they are present. `--preflight` prints WAIT for missing fields before H
and FAIL at or after H ("pause holds, signing blocked").

A fed value that does not validate (a checkpoint hash that does not match the
genesis, a malformed platform id) must not end pause enforcement: a voter that
exits there leaves the producer unpaused, and a nodeos restart would resume
block production past P. For an `operator_fed` config the voter therefore still
loads, logs `ALARM event=cutover.signing_inputs_invalid`, keeps enforcing the
pause, and refuses to sign until the value is fixed and the voter restarted
(`--preflight` prints FAIL). Without `operator_fed`, a bad value refuses to
load, as before.

The voter remembers that its own ceremony finalized in `<config>.finalized`
(bound to the declaration digest). After a restart the fallback pause, which
runs when chain reads fail, works from that marker instead of waiting for one
successful read. The tail scan over H+1..P requires each block to name the one
before it as `previous`, so a reorg between two fetches is caught instead of
leaving one block uninspected.

## CPU units after the cut

XPR's `chain_config` carries CPU caps in microseconds; PulseVM bills and limits
CPU in metering points (`POINTS_PER_US` = 38,000 per microsecond of reference
compute). Imported as-is, XPR's 150,000 us transaction cap would be read as
150,000 points, about 4 us of reference CPU, and ordinary contract actions
(a few index lookups) would be dropped at block build after being admitted.
The converter therefore replaces `max_block_cpu_usage`,
`max_transaction_cpu_usage` and `min_transaction_cpu_usage` with the native
point values (3,000,000,000 / 1,000,000,000 / 100,000), sized against measured
intrinsic costs (`docs/intrinsic-cost-model.md`). A fixed x38,000 does not fit
the `u32` fields.

The caps alone are not enough, and the first block would also reseed the
resource-limits config from `chain_config`. An account's CPU allowance is its
stake share of the virtual CPU limit, and its usage is an accumulator in the
same unit. So the converter also scales, by one factor, every CPU figure in
the resource rows: the resource-limits config (CPU target and max), the
state's virtual CPU limit and block accumulator, and each account's CPU usage
accumulator (`value_ex` and `consumed`). The factor is
`3,000,000,000 / the source's own block CPU cap` (15,000 for XPR's 200,000 us),
read from the source `resource_limits_config` row, so every account's
used-to-available ratio stays exactly where it was on XPR, and the imported
config already equals what the first block derives from `chain_config`. Stake
weights, RAM and NET do not move. The checkpoint hash covers all of it
(`redenominate_resource_rows`, `crates/pulsevm_database/src/xpr_import.rs`).

The table compare applies the same transform to the nodeos side before it
compares (`redenominate_source_tables`) for the three resource tables and prints
a line saying so; every other byte and table is still compared exactly.
`global_property` is the exception to a byte compare. PulseVM's row is 145 bytes
and Leap's is 157. PulseVM now writes the two absent optional proposed-schedule
fields required by the SHiP ABI; the remaining 12-byte difference is Leap's
deferred-transaction configuration, which PulseVM does not implement. A byte
compare can never match, so it used to end in FAILED and operators learned to
accept it. The compare now decodes both rows with the importer's decoder and requires
the chain id and every other field to be equal (the CPU caps are read from the
target as stored, so a wrong cap fails), then prints the two ignored values. A
run that previously needed `global_property` and `contract_index_double`
accepted as known differences should now exit 0 with nothing waved through.

`contract_index_double` and `contract_index_long_double` used to be missing from
the exported state for a different reason: the state-history exporter built the
tables but left them out of its table list, so a restored checkpoint exported
with no double-keyed secondary index rows although the state held them (a
snapshot, restore and export round trip is now a test). Indexers reading the
state-history stream see them too.

`generated_transaction` was missing for the same reason, and a real snapshot
showed it: mainnet at block 413,240,693 has 20 pending deferred transactions, the
importer kept all 20 (from the chainbase sidecar), and the compare reported "20
rows on nodeos, none in the arena" because the exporter had no slot for them. A
fixture chain with no deferred transactions could not show it. The exporter now
lists all 19 tables, and it debug-asserts that its table list and the tables it
builds agree, so the next omission fails every test that exports instead of one
comparison on a real snapshot.

`global_property` also carries Leap's eleven `wasm_configuration` limits
(`max_call_depth`, `max_module_bytes`, ...). PulseVM's are a build constant, so
a source chain that changed one would migrate under limits it never ran with:
contracts valid there could be refused here. The importer now refuses such a
source ("XPR wasm_configuration differs from Pulse's fixed WASM limits (...)"),
and the compare checks the eleven fields instead of skipping them (its line says
whether they were compared; an older row format that states none is reported as
such).

### Calibration of the factor

The factor is a ratio of block caps, not a measurement of cost per microsecond.
Paul Grey's replay of 100,000 XPR mainnet blocks (413,240,694 to 413,340,693,
2.83M transactions, 13.9 hours) on `359d0582` measured it:

- PulseVM charged about 6,950 points per Leap-billed microsecond (sum over sum);
  per-transaction median 5,547, p5 710, p95 13,088. 28.8% of transactions sit at
  Leap's 100 us floor.
- At 15,000 an account gets about 2.2x the transactions per day it had on Leap
  for the same stake (3.7x for the median account), and one account in the
  window comes out below 1x. At 10,000, 1.4% of accounts are worse off; at
  7,000, 14% (21% of the traffic, mostly arbitrage and liquidation bots).
- No transaction exceeded the 1e9 cap (largest 2.5e8); 6.8% fall under the
  100,000 minimum bill; one block metered 3.14e9 points, 105% of the block cap.
- One machine (EPYC-Milan, dedicated vCPU) ran about 10,000 points per
  microsecond against the 38,000 `POINTS_PER_US` assumes: a full 3e9 block took
  300 to 350 ms of the 500 ms slot.

That supports 15,000 and says not to go below 10,000. The number to watch is the
block cap on slower validators, not the per-account factor. Caveats from the
same report: one 14-hour window, bot-heavy traffic (one account sends 19%), and
Leap's microseconds are noisy and include signature checks.

An account whose whole allowance is below the 100,000-point minimum bill cannot
transact; that is about 7 us of XPR-equivalent allowance, below XPR's own 100 us
minimum bill, so nobody who could transact on XPR is locked out by the minimum
alone. Two accounts with 3 us and 13 us allowances were refused on Leap and on
the target alike.

### Two more places microseconds leak in

- **A transaction header's `max_cpu_usage_ms`** was used as a point count, so a
  transaction that set it (imported multisig proposals, deferred transactions)
  got at most 255 points and could never pay the minimum bill. Leap multiplies
  by 1000. Fixed by protocol version 3 (`CpuUnitsInPoints`,
  `docs/protocol-features.md` section 13); it is not active on a chain until its
  upgrade schedule says so. Schedule version 3 at H+1 on every node; the
  cutover release includes this rule in stable builds.
- **A later `setparams`** applies whatever it is given. The chain only checks
  relations between fields, so XPR's microsecond values (a minimum bill of 100)
  would be accepted and put every cap back to a few microseconds. Version 3
  refuses a minimum under `POINTS_PER_US`. Until it is active, any `setparams`
  after the cut must carry point values, and `getInfo` (`block_cpu_limit`,
  `virtual_block_cpu_limit`) should be checked after it. The system contract's
  own global row still holds microsecond values; nothing re-applies it by
  itself, but a governance call that copies it will.

### A payer refused for a bill it cannot see

A transaction that fails at block build leaves a node-local ("subjective") CPU
bill on its payer, which decays over the usage window. Execution subtracts it
from the payer's available CPU, so a payer whose bill exceeds its allowance runs
with a limit of 0 ("CPU limit of 0 exhausted during apply") and everything it
sends is dropped. Admission used to ignore the bill, so the transaction was
accepted every time and dropped every time, and `getAccount` showed no bill.
Admission now subtracts the same bill and says so in the refusal ("available CPU
N (after a node-local bill of M from earlier failed transactions) is below the
100000 minimum"), and `getAccount` reports it in `subjective_cpu_bill_limit`
(`used` and `current_used`). The bill never reaches consensus state and is
per node.

The state-history window oracle (`xpr_apply_history_window`) replays raw XPR
deltas onto a hydrated state. After a converted import its CPU figures are in
different units, so it is only meaningful for tables other than the four above.

## Coordinator status contract (agent side)

The voter reports its own state via `--status` (one JSON line: head vs H,
vote, confirmation readiness, schedule, pause). The coordinator should
expose the fleet view so operators do not poll 21 voters by hand.
Proposed shape (agent repo implements; field names must match exactly so
one dashboard reads both):

`GET /cutover/status` ->

```json
{
  "height": 170,
  "votes_received": ["bp1test", "bp2test"],
  "voted_weight": "8251494346...",
  "total_weight": "1160000000...",
  "quorum": false,
  "schedule_blocked": false,
  "confirmations_received": ["bp1test"],
  "platform_chain_id": "<hex>"
}
```

`voted_weight`/`total_weight` are decimal integer strings (u128 exact, no
floats). The coordinator never decides: it aggregates and serves; the
gate and the contract decide.

## Post-H audit checklist

Run against the live new chain before declaring the cutover complete.
The rehearsal harness automates the same checks; these are the manual
equivalents.

1. **Head agreement.** `getInfo` on every producer: same head number, same
   head id. 2/3 agreement before serving traffic.
2. **Continuity.** Block H+1 exists and its `previous` equals the committed
   H_ID, byte for byte.
3. **State equivalence.** Spot-check migrated accounts against pre-halt XPR
   state with byte-identical authorities (compare decoded key payloads,
   not string forms; key formats differ).
4. **Exactly-once boundary.** Every pre-halt transaction sits at or below H
   on the old chain; every post-halt transaction sits strictly above H on
   the new chain; no txid appears on both sides.
5. **Confirmation set published.** The full confirmation set (one per
   rostered signer) is archived with the manifest so any node can
   re-verify the gate decision offline later.

## A node that is killed

Paul Grey sent `kill -9` to a target node twelve minutes after the cut and it
refused to start with `database revision 732011 does not match block log end
732032`. The arena reached disk only on a clean shutdown, so a kill left the
state at the restore revision while the block log (appended on every accepted
block) had moved on, and the only recovery was an offline replay opt-in.

Now every accepted block's state change is appended to `arena_wal.bin` in the
database directory and fsynced, after the block log and the in-memory commit. On
start the node loads `arena_state.bin` and replays the log onto it, so it comes
back at its last accepted block with the exact state it had (the state root is
compared in the tests). What to expect:

- **Normal kill.** The start logs `the previous run did not shut down cleanly:
  recovered N accepted block(s) from the arena write-ahead log`. Nothing to do.
- **Killed between the block-log append and the state flush.** The block log is
  one block ahead of a state that is otherwise intact. The node drops that one
  block (it is re-fetched from peers) and starts, without the offline-replay
  opt-in. State-history logs are rewound by the same block.
- **Killed between the history logs and the block log.** An accept writes the
  trace and chain-state logs first and the block log last, which is the marker
  that the block was accepted. A kill in between leaves those two logs one block
  ahead. They are cut back to the block log's end on every start (the start logs
  `dropping the incomplete accept record`); before this the node's next block was
  refused as `missed a block in trace_log.log`. Found by the real `kill -9` test
  below, not by the hand-built ones.
- **Killed at the activation block.** The activation record for a protocol
  upgrade is written just after the block's state is flushed, so a kill between
  the two left version 2 executed but unrecorded, and the boot check refused to
  start. On start the node writes back the record for the last accepted block, and
  only that one, and only when this node executed that block (the block log holds
  more than its first block). An upgrade scheduled at or before the height a chain
  restarted from was never executed here and is still refused (`N = H+1`, above).
- **Killed during the write.** A partial final record is discarded and the log is
  trimmed to the last complete one before anything is appended.
- **A clean stop** folds the log into the checkpoint and removes it.
- **Bounded size.** When the log passes `arena_wal_max_bytes` (default 4 GiB) the
  next block writes a new checkpoint instead and starts the log over. At
  mainnet size that checkpoint is a pause of some seconds on that block, once per
  threshold; lower the value to bound replay time after a crash, raise it to
  checkpoint less often.
- **A directory from before the log existed**, or one whose log was lost, is a
  real mismatch if the gap is more than one block, and still needs the
  offline-replay opt-in (`allow_replay_recovery`) or a fresh state sync.
- A state-sync snapshot being served from a running node does not disturb the
  log (exporting a checkpoint no longer resets its bookkeeping); installing a
  synced state replaces the log with the new checkpoint.

The tests kill a node two ways. Most drop the controller without closing it, on
a fresh chain and on a chain restored from a migration checkpoint, with a torn
final record, between the block-log append and the flush, and with a snapshot
export in the middle. One is a real `kill -9`
(`a_process_killed_with_sigkill_restarts_at_a_block_it_had_accepted`): it re-runs
the test binary as a child that keeps accepting blocks, sends it SIGKILL at a
different moment in each of six cycles, and requires the directory to reopen at a
block the child had reported accepted, with every account those blocks created
and a log that agrees with the state, then takes the next block. It does not
involve MetalGo or the plugin; a kill of those on a live network is still Paul's
check.

## Restarts, damaged files and load (round 11)

Paul Grey ran `fa777b69` and `6425eb82` on live nodes: the compare against a real
mainnet snapshot passed, and every one of 23 `kill -9` of MetalGo and the plugin
came back without the opt-in. The runs also found what is below. How each was
found says what the tests have to look like: they compare a restarted node with a
node that never stopped, they kill at a chosen microsecond, they damage files, and
they run at a realistic transaction rate. Every one of those now has a test, and
the `Resilience` workflow runs them on every push and weekly.

**The state root depended on where blobs sat in the arena.** A node that had
restarted computed a different root from its first transaction on, and the nodes
that never stopped agreed with each other (three roots, then five, across five
nodes; checkpoints written at the same height differed in size). The root hashed
each row's raw blob offsets and the whole blob arena, dead spans included, and a
restart loses the free list, so the layout of a node that restarted stopped
matching the others. The root now hashes each row with its blob references
resolved to their bytes. It does not depend on allocation history. `state_root`
is not in a block header and account reads agreed throughout, so the chain kept
going; what it broke was comparing a restarted node's state, and a state-sync
snapshot taken from one. The value of the root changed with this fix, so a root
recorded by an earlier build does not match one computed now (the per-table
chainbase roots in the golden replay are a separate, independent fingerprint and
are unchanged). Every table type must say where its blob references are
(`ArenaObject::blob_ref_offsets`, required with no default: a hand-written
implementation that forgot one was exactly how the contract-row table kept
diverging after the first fix). When two nodes disagree,
`arena_tables_differing_from` names the table.

**The log has a checksum and a version.** Each record is
`[length][payload][SHA-256 of length and payload]` behind an 8-byte `PVMWAL03`
header. Whether damage is a crash or an alteration is decided by what follows it,
not by the shape of the damage. If a record cannot be completed or does not
verify, the node looks for any intact record after it. None: what is left is the
remains of a write that was cut short (a partial record, zeros of any length,
garbage), and it is trimmed. One: the file was altered in the middle, and the node
refuses to start, naming the byte, **and leaves the file exactly as it is**. Round
11 left two holes in this. The checksum did not cover the length, so one flipped
length made every valid record behind it look like a torn tail and they were
deleted from the file; and a zero-filled tail longer than exactly 40 bytes was
refused as "altered", which is what a torn write on a filesystem that extends a
file before the data lands looks like. A zero-length header used to hang the
plugin at start-up with nothing logged; it is a torn write like the rest, and a
failed initialization is now logged by the plugin. A log from an earlier build
(`PVMWAL02` or none) is refused by name: stop that node cleanly with the build
that wrote it, or resync. The directory is fsynced after the checkpoint's rename,
the log's creation and its removal, and the protocol and metadata files', so a
power loss cannot bring back a log the checkpoint replaced. Power loss itself is
not run here (a `kill -9` cannot show a missing directory fsync).

**Replay no longer trips over a block that moves a unique key.** Applying a
logged block one row at a time, in the order the rows were first touched, failed
with `delta secondary key conflict` when a block gave a row the key another row
held (or removed a row and reused its key), although the live table had done it in
a safe order. A node would have refused to start after a kill. A block is now
applied in two phases, all the old rows out of the indexes and then the new ones
in.

**State history off is a normal setting, and switching it back on is refused.** It
used to be treated as an offline replay: the block log was not fsynced and no
per-block log was written, so a killed node came back with nothing since its last
clean stop and re-fetched every block from its peers. Only state history off
together with the replay opt-in (`allow_replay_recovery`) is a replay now. A
node that ran with state history off and is then started with it on is refused at
start with what to do: leave it off, or stop the node and move the trace and
chain-state log files aside (they begin again at the next block, without the
missing history), or resync. It was a node that came up and then refused its next
block as `missed a block in trace_log.log`.

**Block time under load.** A block's timestamp is the later of the clock and one
slot past its parent. Asked for blocks faster than one per slot (about three a
second), the builder stamped each a slot further ahead, and past 20 slots (10
seconds) verifiers refused the block and the network split 2-2. The service now
waits for the next slot, up to six slots (3 seconds), before it takes the
controller lock, having detached the pool first; a chain already further ahead than that is answered with an error
and retried on the next 500 ms tick, so the clock catches up instead of the chain
running on. This changes only when this node builds, not what verifiers accept.

**Checkpoints are staggered.** Every node's log starts empty at the same height
after a cut and grows at the same rate, so with one threshold they all fold on
the same block, and a fold at mainnet size is a pause of about 4 seconds (Paul
measured 4.2 to 4.4 s for 2.09 GB). The threshold is now the configured
`arena_wal_max_bytes` plus up to as much again, chosen from the node's identity
(the id the host gives the node, so hosts that share a producer name and a path
still differ), so
nodes fold at different times. A fold still pauses the node that does it. Raise
the setting to fold less often, lower it to bound replay after a crash.
Debug-level logging is now opt-in: it hashes the whole state after every block to
print it, which is also why accept took about 0.5 ms longer than it should in
the measurements. Set it with `log_level` in the chain config. A
`PULSEVM_LOG_LEVEL` environment variable only works when the plugin binary is
launched directly: MetalGo starts the plugin with a minimal environment of its own
(only its engine address), so no variable set on the host reaches it. The same
holds for `state_root_log_every` (chain config), which logs the state root at info
level every N blocks so the nodes of a test network can be compared; it is off by
default because the root is a hash of all state.

**Deferred transactions pending at H.** Whether they run on the new chain is a
choice with a cost either way, and it is made when the checkpoint is converted.
`xpr_import_check` leaves them as the source had them by default (they run when
due, or are retired if expired, the design in `docs/xpr-achain-migration.md`
section 13); `--expire-deferred` retires every one in the new chain's first block
without running it, refunding its RAM and keeping only its id, which is what a
Leap 5 producer does. A Leap 5.0.3 source expires them regardless of the
protocol-feature list, so on a fixture of that kind the default makes the target
run transactions the source would never run; on an EOSIO 2.x source (XPR's own
nodes) running them is what the source does. Which one a real cut needs depends
on the nodeos XPR mainnet actually runs, and that has to be confirmed, not
assumed. The choice is part of the checkpoint and so of its hash: every BP must
pass the same flag, and the pinned hash refuses a BP that did not. The vote scan
reads a deferred receipt (a bare id): an expired one never ran and is skipped, an
executed one cannot be inspected, and the scan stops only if the votes it found
do not account for the weight the contract counted.

The mode is recorded in the migration manifest (`deferred_policy`: `execute` or
`expire`; absent in manifests from earlier builds). Under `expire` the converter
sets both `delay_until` and `expiration` of every pending row to the epoch, so each
is due in the first block (not after a delay that can be a day) and is already
expired there. A validator does not have to rebuild the checkpoint to learn the
mode: `xpr_verify_manifest` restores it and fails if the manifest names one mode
and the rows show the other, and `xpr_19_table_compare` prints the mode its rows
show. The restore-side check that no deferred row falls due inside the pause
window passes trivially under `expire`, since every row is due at the epoch and
is retired rather than run.

**`setparams` also floors the block cap.** The transaction cap must be 100 times
the minimum bill (round 10); the block cap must now be 1000 times it. A block cap
just over the guard fit about ten ordinary transactions. The converted chain's
figures are 10,000 and 30,000 times. Both are guards against unit mistakes, not
proof that a configuration is sensible.

**Operating notes.**
- If the plugin is killed and MetalGo is left running, MetalGo does not relaunch
  the plugin and the chain stays down until MetalGo is restarted. Supervise
  MetalGo, not just the plugin.
- A disk that fills stops the plugin and MetalGo shuts the chain down (no restart
  loop); once there is space the node recovers on its own.
- The `rewinding block log` line is printed twice at start-up. It is cosmetic.
- A record `<config>.finalized` written by an earlier voter build (format 1) is
  not read. Delete any such file before a real run: one paused Paul's live
  producer for the previous round's P.

## Power loss, a full disk, a dead plugin

**Power loss: run MetalGo on pebbledb.** After a power cut a node can refuse to
start with `proposervm height index (N) should never be lower than the inner
height index (M)`. The cause is two durability levels in one process pair: this
VM fsyncs every accepted block, while MetalGo's default database (`leveldb`)
writes without fsync, so the host's index of accepted blocks can lose its last
writes and come back behind the VM. MetalGo's repair
(`proposervm/vm.go: repairAcceptedChainByHeight`) can roll its own index back when
the VM is behind, never forward, so it refuses. MetalGo persists its index
*before* it tells the VM to accept (`postForkBlock.Accept`: outer, then inner), so
with synced writes the host can never be behind. `pebbledb` syncs each write
(`database/pebbledb/db.go`, `Sync: true` by default; batches commit with it).

Set `"db-type": "pebbledb"` in the node config for every node of the new network,
and put it in the T-14 production node-config checklist: **today only
`scripts/run-local.sh` sets it** (override with `PULSEVM_NODE_DB_TYPE`).
MetalGo keeps leveldb in `<db>/<network>/v1.4.5` and pebble in
`<db>/<network>/pebble`, so **changing `db-type` does not fail. It quietly opens
an empty database beside the old one.** Paul measured both directions:

- pebble to no flag: the node ran on a new, empty leveldb, unsynced, and nothing said so;
- then back to pebble: refused with the proposervm height-index error above, the
  power-loss refusal caused by configuration alone.

So moving a node's database type means clearing its `chainData` too, and the type is
chosen when the node first starts. The same class of mistake that pebble alone does
not fix: a host database wiped or restored while `chainData` is kept, a `db-config`
with `"sync": false`, or storage that does not honour flushes. `verify-restarts` now
checks what the running node opened (the pebble directory is present, no leveldb
`CURRENT` file beside it, and the node's own "opening pebble" log line shows
`"sync":true`), not just that an `OPTIONS-*` file exists, which one left behind
satisfied. Measured cost (Paul): about one `fdatasync` per accepted block, 206 to
311 microseconds, 2.7 to 3.8 MB/min written; block build to accept time was not
measurably different (consensus dominates). MetalGo's memory still grows on pebble
(76 to 750 MB over 173 minutes on one node); whether it plateaus at the cache size
is not measured.

What was and was not checked: the order and the sync options were read in MetalGo's
source, and Paul's recorded power-cut replay on pebble refused 0 of 230 images
(against 99 of 155 on leveldb).

**A full disk, or a plugin that died.** Neither is tested here: there is no
disk-full case in the test suite, and what the plugin does with a failed write is
whatever its error path does, not a designed behavior. What is known from running
the rehearsal network is that MetalGo does not relaunch a plugin that has exited,
so a node whose plugin is gone keeps running without its chain until MetalGo
itself is restarted. Free the space (or find why the plugin exited in its log),
then restart MetalGo. The write-ahead log and block log recover as after a kill;
that part is covered by the kill tests above.

**Clock skew.** A node whose clock runs behind its peers sees the next slot that
far ahead. It waits up to six slots (3 seconds) and reports a larger skew as an
error each 500 ms tick instead of sleeping through it; verifiers accept a block up
to 20 slots (10 seconds) ahead. Keep NTP running on every producer. The thresholds
are tested (`pacing_rides_out_a_clock_three_seconds_behind_and_reports_more`).

**Files the node rebuilds.** The `.index` files beside the state-history logs are
rebuilt from the log on open when they lag it (`state_history/log.rs`, open-time
recovery). How long that takes at mainnet size has not been measured here.

**The checkpoint file a node writes for itself.** `arena_state.bin` is a node's own
checkpoint and depends on that node's live layout, so two nodes at the same height
can hold different bytes while holding the same state. What is compared between
nodes is the canonical state root, and what a node serves or exports for state
sync is the canonical form: the same bytes from any node at the same height
(tests `an_export_is_the_same_bytes...` and `a_node_that_restarted_exports...`).
Do not compare `arena_state.bin` files byte for byte.

## State sync, damaged history logs and the write-ahead log (round 13)

**A node that restarts could stall the chain.** While a node state-synced, the
plugin answered the host's wait with "build a block" whenever the mempool held a
transaction. The host's state syncer only accepts "sync finished", and it takes one
notification per subscription, so it never listened for the end of the sync again:
the node stayed in state sync until it was restarted by hand, and with another node
also restarting the chain stalled. The plugin now keeps the engine state it is
given and, while the engine has it state-syncing, reports nothing but the end of
the sync (`next_engine_event` in `crates/pulsevm/src/main.rs`, four tests).

**Nodes no longer state-sync for a few blocks.** A summary no more than
`state_sync_min_blocks_behind` blocks (default 1024) ahead of the node's tip is
skipped and the node fetches those blocks instead. Before, a node 5 blocks behind
installed a snapshot, which rebases the block log and dropped its history (78 MB to
3 MB). A fresh node and a node far behind still sync. Set it in the chain config
(`0` syncs whenever a summary is ahead).

**A cut during a state-sync install now recovers by itself.** The install swaps
the arena, the block log and the history logs and marks the window with
`state_sync_installing`. A cut inside it can leave pieces from two heights, so the
node refused to start until its data was moved aside by hand (the host then logged
`error creating chain ... EOF`). On start the node now moves everything in its data
directory into `state_sync_abandoned/<time>/` (the two newest are kept, so the
damage can be examined) and starts as a fresh node, which the host syncs again, and
logs `ALARM event=state_sync.install_abandoned`. It only happens for a node that
was being synced from others. Moving the data aside by hand, which Paul did, is the
same recovery and rejoined in 2.2 s.

**Zero tails on the history logs.** A power cut can leave the trace, chain-state or
block log longer than its data, the tail all zeros. The node opens all three logs
with magic 0, and a zero header matches magic 0, so the zeros were read as entries
for block 0 and the node refused to start with `missed a block in trace_log.log`.
The earlier fix only ran when the expected magic was not zero, which is never the
case on a node. An all-zero remainder is now trimmed whatever the magic; zeros
followed by data are still refused. The in-place case (the last entry zeroed) drops
that entry.

**The write-ahead log checksum is keyed** (`PVMWAL04`). A plain hash of length and
payload can be computed by anyone, and a payload carries contract row bytes
verbatim, so a transaction could store 56 bytes that read as a valid record. Inside
a torn final record that proved the file "altered" and the node refused to start; one
such row per block would keep it from recovering without a manual fix. The log now
starts with a random 32-byte key and every digest includes it; a contract cannot read
that file. A file of nothing but zeros (the window between removing the log at a
fold and the next accept creating it) is an append that never happened, not a log
from an earlier build. **This and the canonical export are format changes with no
gate:** every producer must run and convert with the same build. Fine before launch;
it is part of the launch checklist.

**Exports refuse corruption.** A blob reference outside its arena, or a table whose
blobs exceed 4 GiB, makes a canonical export fail instead of writing an empty blob or
a truncated offset that looked like a valid snapshot.

**The manifest must record the deferred mode.** `deferred_policy` is required: the
verifier and the node's restore gate refuse a manifest without it or with an
unknown value, as well as one that disagrees with the checkpoint's rows. It is not
inside what the halt pair signs; the checkpoint hash the confirmation does bind
already commits to the deferred rows, so an edited field can mislead a reader but
cannot change what the chain does. Binding it into the confirmation digest would
change the ceremony format and was not done.

**Refused blocks are summarised, not hidden.** A node that is behind refuses every
block of a peer that is ahead (about 1.3 million warnings in two hours). Lowering the
level would hide a real failure among them. The first refusal in a ten-second window
is logged in full; the rest are counted into one summary with how many, over which
heights and why the first was refused.

**How this is checked end to end.** The `faults` scenario of
`.github/workflows/cutover-e2e.yml` (`VERIFY_FAULTS=1 run-handover.sh
verify-restarts`) runs on the live five-node network: zero tails on the three
history logs, a zero tail and then a flipped record in the write-ahead log (refused by
name, file left alone, then put back), the install marker, a node state-syncing with
transactions pending (the stall only happens if MetalGo offers a summary ahead of the node, which a test cannot force: the stage says in its log whether a sync ran, and the unit tests of `next_engine_event` are what fail without the fix), and a node a few blocks behind; each must rejoin and agree
with the nodes that never stopped, at all five nodes' roots. A real power cut
replayed at every write needs a recording block device and is not reproducible on a
hosted runner; Paul's box remains that check.

## Independent review of the cutover (round 14)

Four reviewers who had not seen the earlier work read the restore gate, the voter,
crash recovery and state sync, and the untrusted-input parsers, by reading only.
Each finding below was checked against the code before it was acted on.

**Fixed, each with a test that fails without the fix:**

- **A wrong config disarmed a live pause (voter).** Restarting an armed voter with a
  config whose digest matched nothing (a typo in the roster, contract or chain id)
  moved the record aside without asking the chain, so the voter never paused and a
  later nodeos restart resumed production past P. It now supersedes a record only
  when the chain says that round was replaced, and otherwise holds the recorded pause.
  The same check applies when a restart finds a record for the current config: if the
  chain no longer shows the round, it is not restored.
- **The degraded voter gave up on one read.** It stopped enforcing on a single read
  that did not show the recorded round (a node restarting from a snapshot, a
  microfork). It now needs three in a row and enforces meanwhile. The state file is
  fsynced, with its directory.
- **A snapshot's id counter was not part of the state root.** A peer's snapshot could
  carry a forged `next_id` and install under a root that matched; the node then minted
  different ids than its peers from the next block. The counter is hashed
  (`arena-table-v3`), bounded, and a table's live-row count is checked against the
  bytes present before anything is sized from it. A checkpoint with two sections for
  one table, or bytes after the last one, is refused.
- **Peer-reachable allocation and amplification.** A chunk request is limited to one
  chunk (it was a peer-chosen u32 copied under the controller read lock). A sparse
  payload cannot declare a file far beyond what it carries (eight header bytes could
  ask for a terabyte file that was then read into memory). The write-ahead log's
  damage scan has a work budget and refuses when it runs out, instead of spending
  quadratic time on bytes a transaction can plant.
- **Boot-time checks tied restarts to mutable state.** The source-schedule binding and
  memo-account checks read the checkpoint's rows on every start, including after the
  chain had advanced, so a later edit of those contract rows by the migrated system
  account would have refused every restart. They now apply only while the arena is
  still the checkpoint.
- **The offline verifier could pass a bundle the node refuses.** It never decoded the
  attached source block or the restored rows. It now calls the node's own functions
  (`verify_migration_source_block`, `verify_restored_deferred_rows`,
  `verify_restored_input_transactions`), so there is one implementation.
- **The ceremony tool.** `confirm` refuses a `--checkpoint` that is not the genesis
  pin, and a confirmation below a strict two-thirds quorum. Keys can be given with
  `--key-file` (owner-only); `--key` still works but warns that it puts the key in the
  process list.
- **The quarantine of an interrupted install** moves the marker last, so a kill
  part-way is finished by the next start. Quarantine entries are no longer pruned
  automatically: an older entry may hold the node's last usable checkpoint.
- **A zeroed block-log tail could be decoded and served as a different block.**
  Startup checks the recent tail; every historical block read now checks exact
  decoding, height, recorded id, and transaction Merkle root. Damaged entries fail
  with a resync diagnosis.
- **A node cut after the block-log append could forget a durably accepted block.**
  The one-block-ahead case preserves the logged bytes, rewinds the logs to the
  durable Arena revision, then revalidates and replays the block through ordinary
  first-time validation.
- **A schedule-pin abort was forgotten on restart.** The voter now fsyncs a
  declaration-scoped abort marker before exit; restart of that same declaration
  stays aborted.
- **A blank startup ceremony read could discard an armed pause.** Empty reads now
  count as unverifiable, and startup requires three matching replacement reads
  before moving an older pause record aside.
- **A node reports its build.** `getInfo` carries `pulsevm_build` (git commit, write-ahead
  log format, state-hash format) and the node logs it at start; the rehearsal fails if
  its five nodes report different builds. This is the same-build requirement made
  checkable.

**Remaining rehearsal blockers and operational limits:**

- **A validator that is itself state-syncing stops answering consensus polls.**
  The corrected box test found that a non-validator downloaded the same 357 chunks
  while five validators made 67–70 blocks, with 1.8% failed polls. A syncing
  validator left the five-validator network at 0–12 blocks in each ~35-second
  window, with 27% of one node's polls failing. Serving chunks is not the cause.
  The 21-producer calculation suggests a 4.8% validator may be covered by the
  8.33% max-benched-stake cap, but this has not been measured. The four-host
  rehearsal must include a validator sync and record block production, poll
  failures, bench state, and resume time. Do not claim mainnet-safe until the
  21-producer or equivalent weight test passes.
- **State-summary intervals are network-wide settings.** If validators use
  different `state_summary_interval` values, they request different fixed heights;
  the tested mismatch produced no state sync and a 3,546-block replay without a
  useful diagnostic. Compare `get_info.state_summary_interval` on every validator
  before the run and keep it identical. During bootstrap the VM now skips expensive
  summary construction and resumes at the next aligned height after normal
  operation.
- **A damaged snapshot is retried from another peer.** Each transfer is pinned to
  one peer so the final authenticated envelope hash identifies a bad source; on
  transfer or integrity failure the VM retries the complete bounded snapshot from
  another connected peer. Per-chunk proofs are still absent, so a bad peer can cost
  one full transfer before it is identified. Block replay remains the final fallback.
- **A VM that refuses to start or stops accepting blocks can still be counted by
  MetalGo.** The plugin cannot stop MetalGo or remove the validator from polling.
  The in-plugin watchdog was removed; a nonzero `dead_chain_shutdown_after_secs`
  now fails initialization with an explicit explanation. Use a MetalGo-side
  health integration or host supervisor that stops/restarts the host; this remains
  external to this repo and is a rehearsal gate.
- **Provider and history integration is not rehearsed here.** The local
  cutover harness boots validators only; it does not boot an API-only provider,
  connect Hyperion, validate the history router across H, or measure XPR archive
  storage at mainnet volume. Run the provider gate in
  `xpr-achain-migration.md` on the provider box and attach SHiP continuity,
  Hyperion row-count, restart, and archive-size evidence before LIVE.
- **The live five-node environment is not configured in this checkout.** The
  handover script can verify Pebble and synced writes on every live node, but that
  check has not been run against the rehearsal hosts here. Do not treat the local
  Compose stack as evidence of production database type.
- **MetalGo memory growth and the two-of-five availability result remain measured
  operational limits.** There is no MetalGo validator process or mainnet-sized
  state-sync run available here to profile. Five equal-weight validators also stop
  making progress when only three remain under the current polling threshold; change
  the validator set or its consensus availability assumptions deliberately if that
  fault tolerance is not acceptable.
- **A second round on a producer paused at an older P needs a coordinated operator
  reset.** `cutover.cpp`'s `init` refuses to re-freeze a ceremony that already
  collected a vote for 7 real days (`vote_window_us`) unless that window expired,
  so the only practical way to redo a voted round quickly is a fresh ceremony
  contract account. A voter does not auto-release an old pause merely because
  local config names a newer declaration on a different contract; the chain
  check that could tell them apart re-reads the *recorded* contract specifically
  (by design, to tell a genuinely-replaced declaration from a config typo that
  matches nothing), so it never sees the new account's ceremony. Naively
  restarting the voter against the new round does not crash: it degrades into
  holding round 1's own pause height and casts no vote for round 2 — a real
  stuck state, just a quiet one, not a loud one. Stop the old voter on every
  validator, then run `xpr_cutover_voter --config voter.json --release-old-pause
  --expected-old-digest <old declaration digest>` on each producer host. It
  verifies the local pause record and producer/chain identity, resumes that
  producer, verifies the API response, and archives the old record. Only then
  create and finalize the new declaration, install the new voter config, and
  start the voters together. This is an explicit operator break-glass path, not
  automatic agreement that a new declaration may replace an old one. This whole
  cycle (round 1 pause, a naive round 2 holding it with no vote cast,
  `--release-old-pause`, round 2 completing) now runs end to end in CI against
  a stubbed producer API, in `contracts/cutover/test-voter.sh`.
- **A missing Arena checkpoint with old logs now quarantines the whole data
  directory and boots fresh.** It does not guess which quarantined files form a
  usable checkpoint. The host must complete a new authenticated state sync. A cut
  during quarantine leaves a durable marker so startup can finish moving the files.
- **Quarantined pre-sync data is retained for operator recovery.** Authenticated
  state sync no longer deletes the `state_sync_abandoned/` directory. Keep it until
  an operator has inspected the newest entry and explicitly removes it; monitor disk
  usage and include retention in the data-volume budget.
- **Not changed:** the freshness bounds in the manifest are asserted by the exporter,
  not committed by the ceremony; the multi-gigabyte checkpoint hash runs before the
  cheap pair verification; the declaration's source chain id is signed but not compared
  to the restored state (the confirmation still binds this chain's block and
  checkpoint, so this is defense in depth).
- **Smaller crash-recovery items** (two non-fatal install error paths that leave a
  split state until the next restart quarantines it; the write-ahead log is read into
  memory whole at recovery; the history logs cannot tell a corrupt size from a torn
  tail) are recorded, not changed.

**What now checks this, beyond the unit tests:**

- **Every crash point of an accept** (`every_crash_point_in_an_accept_recovers_to_a_height_the_reference_agrees_with`).
  An accept writes the trace log, the chain-state log, the block log and the arena
  write-ahead log in that order, each synced before the next, so a crash leaves a
  prefix of that order plus possibly a torn piece of the next file. The test builds
  every such state from a real run (four steps, each with nothing, half, one byte
  short, or a zero-filled record of the next file) and requires each to recover to a
  height whose state root matches a node that never stopped, then take another block.
  With the history-tail trim removed it fails with the error found live in round 10
  (`missed a block in trace_log.log`). It models what reaches disk in fsync order; it
  is not a real power cut (that stays Paul's replay), and it does not cover a disk
  that reorders synced writes.
- **Exhaustive checks of the voter's two decisions** (`a_record_is_only_removed_when_the_chain_answered_that_its_round_is_gone`,
  `the_degraded_voter_stops_exactly_on_three_replaced_reads_in_a_row`). The decisions
  are small pure functions the voter calls (`recorded_action`, `pause_only_step`);
  the tests run every (record, chain answer) pair and every sequence of answers up
  to length 9. This is a model check in plain Rust, not TLA+ (no Java here); it covers
  those two decisions, not the whole voter.
- **Fuzzing** (`fuzz/`, workflow `fuzz.yml`): the write-ahead log, the checkpoint, the
  snapshot envelope and sparse payload, and the history logs, each fed arbitrary
  bytes. A 40-second local run of each (about 800,000 executions) found nothing. That
  is a smoke result: random bytes mostly fail a checksum early, so there is no claim of
  depth without a seed corpus of real files.
- **Replay scanner** (`scripts/plw-replay-tool/`): the Downloads harness is now kept
  with the repo, its WAL damage scan mirrors the current `FramePrefix` revision and
  table-count filter and budget, and scanner-model tests run in CI. Full
  `dm-log-writes` image replay and live start-tests still require Linux, root, loop
  devices and the target network.

## The state summary no longer stops the node (round 15)

*Superseded in part: the per-request build described first below (copy under the
controller, build off it) was replaced by summaries at fixed heights, described at the end
of this section. The measurements and the reasons stand.*

Paul measured the export of a mainnet-size state for a state summary at about 9
seconds and a 7 GB peak. `get_last_state_summary` took the controller exclusively and
kept it for the whole export, so while a peer was being served a summary this node
handled no block. A node that restarts or state-syncs asks its validators for their
last summary, so by the code this could pause each of them in turn. That inference
has not been measured on a network; the 9 seconds and 7 GB are Paul's measurement.

What changed:

- The controller is held only to **copy out** what the export reads: the rows and
  blob bytes of each table, no indexes or undo state (`Db::freeze`). Repacking,
  hashing and encoding the copy (`SnapshotJob::build`) runs on a worker thread
  without the controller, and the controller is taken again only to cache the
  result. The summary describes the block the state was copied at, not the tip by
  the time it is built, so it stays consistent with its snapshot when blocks are
  accepted meanwhile (a test accepts blocks during the build and then state-syncs a
  fresh node from the summary).
- Builds are serialized, so several peers asking at once cost one build instead of
  one full snapshot in memory each.
- The canonical bytes are no longer written to a file and read back, and the copy is
  dropped as soon as they exist.

Measured on a synthetic 624 MB state (release build, a laptop): the database is held
for 188 ms now, against 862 ms for the old route. The rest of the work (about 750 ms
there) happens off the lock. Run
`cargo test -p pulsevm_arena --release --test freeze_cost -- --ignored --nocapture`
(`FREEZE_ROWS` sets the size). Expect the hold to scale with state size at memory-copy
speed (roughly 0.5 to 1 s at 2 GB); that is an extrapolation, to be replaced by Paul's
measurement on the mainnet snapshot. Peak memory is lower than before but not small:
the copy and the canonical bytes exist together while the copy is repacked.

**Fixed-height summaries and the corrected sync finding.** Each validator builds a
summary only at network-agreed multiples of `state_summary_interval`. `getInfo`
reports this setting as `state_summary_interval`, so operators can compare it on
every validator. All nodes must use the same value; a local mismatch silently
changes available summary heights and can force block replay. The reported box test
used 32 and 256; the production default 4096 was not observed to produce a summary
within the test window.

- A normal-operation node builds summaries at aligned heights (default 4096, about
  half an hour at two blocks a second; 0 disables summaries). It skips expensive
  summary work while MetalGo reports the VM bootstrapping or state-syncing, then
  resumes at the next aligned height. This avoids generating every intermediate
  snapshot during catch-up.
- When the block at such a height is accepted, the controller copies the state out
  (the only work under the lock, about 1.2 s on the mainnet arena, once per interval on
  every validator at the same block). The state root, the repacking, the sparse encoding
  and the hash all run afterwards on a worker thread, from the copy, and the result is
  written to `<data dir>/summaries/<height>.snapshot` and `.summary`. The newest two
  are kept.
- `get_last_state_summary` returns the newest kept summary that is at least
  `state_summary_min_age` blocks (default 8) below the tip, or `NotFound`.
  `get_state_summary(height)` returns the kept summary for exactly that height, or
  `NotFound`. Neither builds anything or waits for a build.
- Orphaned `.snapshot` files and invalid summary pairs are removed on store open;
  they are rebuildable. Quarantine directories from interrupted installs are
  retained after a later successful sync for operator inspection and cleanup.
- Chunks are read from the snapshot file and need neither the controller nor a
  full-size copy in memory. A chunk request is limited to one chunk.
- A node that joins when no summary is old enough catches up by fetching blocks, as
  does one within `state_sync_min_blocks_behind` of the summary. On a chain restored
  from a migration checkpoint the first summary is at the first multiple of the interval
  above the restore height.

The corrected box test showed that **the syncing validator** stalls consensus polls; a
non-validator synced 357 chunks while the five validators produced 67–70 blocks with
1.8% failed polls. Chunk serving itself was cheap. During a validator sync, peers made
0–12 blocks in ~35 seconds and one node failed 27% of polls. The five-node rehearsal
cannot establish mainnet behavior: with 21 equal validators, one has 4.8% stake, below
the reported 8.33% max-benched-stake cap, but this must be measured at 21 validators.

The measured 2.09 GB state costs 1.18–1.25 s for the held copy, 8.7–8.8 s for the
background build, 2.4–2.8 s to write, and 7.56 GB peak memory. A corrupt snapshot is
detected by its envelope hash only after downloading the full payload; per-chunk proofs
is now retried from another peer after the full transfer fails integrity validation;
per-chunk proofs would avoid that first wasted transfer. Plan large validator syncs and
keep them rare until the validator-poll test is green. The cutover fault stage requires
state sync to start and finish, but the 21-producer polling result remains unmeasured.
The copy under the lock at each summary height, the cost of every kept summary on disk
(about the size of the state, two kept), and the memory of a build (the copy and the
canonical bytes together) remain costs of this design.

## The voter after a failure: restart, degraded mode, state file

- **A config fix needs a restart.** The voter reads its config at start. Fixing
  a bad fed value (a mistyped checkpoint hash, for example) in the file does not
  change a running voter: it keeps logging
  `ALARM event=cutover.signing_inputs_invalid`, keeps the producer paused and
  refuses to sign until it is restarted with the corrected file.
- **State file.** Once the voter sees its own ceremony finalized it writes
  `<config>.finalized` (JSON). It is bound to the declaration digest, H, P, the
  schedule version, the source chain id, the producer, the node and producer API
  addresses and the ceremony contract. The config directory must be writable. A
  failed write logs `ALARM event=cutover.pause_state_unsaved` and is retried on
  every poll, including polls where the chain reads fail, until it lands: until
  then a restart or a broken config forgets the pause. A file in the old format
  (a bare digest) is ignored and rewritten. A dry run never writes it: it
  enforces nothing, and a record it left would make a later degraded start pause
  the real producer.
- **A different declaration retires the old record.** If the config describes a
  different declaration than the record (an aborted round re-declared), the
  voter moves the old file to `<config>.finalized.superseded` at start and keeps
  it as the audit record. Otherwise a later config failure would enforce an
  abandoned round's P on a live chain.
- **A changed P or schedule version is refused.** The declaration's quorum covers
  H and the member set but not P or the schedule version. If the record says
  this declaration finalized with P and the config now says P+1, the voter
  refuses to start rather than sign a confirmation nobody agreed to: the fleet
  may already be paused at the old P. If every voter really is moving to the new
  value, move the state file aside (it stays as the record) and restart. The
  refusal does not end the voter: it logs `ALARM event=cutover.voter_changed_round`
  and keeps enforcing the pause recorded for the old P, signing nothing. Exiting
  there let a nodeos restart resume production past P (head 887941 to 887975 in
  Paul's run). The agent should independently refuse a confirmation whose pause
  height differs from the event's stop height; the voter's own guard rests on the
  state file, and deleting the file (as the refusal says to) removes it.
- **A config that stops loading keeps the pause.** If the config cannot be
  loaded after the voter recorded a finalized round (malformed JSON, an
  unreadable key file, a failed validation), the voter does not exit: exiting
  would end pause enforcement and the next nodeos restart would resume block
  production past P. It logs `ALARM event=cutover.voter_degraded`, keeps the
  producer paused from the recorded state, and signs nothing. Restart it with a
  working config to sign. Two things still stop it: `enabled = false` in a config
  that parses (an explicit stop), and the absence of a recorded round (the pause
  was never armed). `--preflight`, `--status` and `--print-digest` still exit 1
  on a bad config.
- **Degraded mode checks the record against the chain.** Each poll it reads the
  ceremony table (it needs only the node URL and the contract name from the
  record) and enforces the pause only while the chain still shows that
  declaration finalized. If the chain shows a different declaration, an
  unfinalized one or none, it logs `ALARM event=cutover.voter_stale_state`, does
  not touch the producer and exits 1, so a stale record cannot pause a live
  chain. If the table cannot be read (or the record predates the contract field)
  it enforces anyway: pausing for a round that may be abandoned is the lesser
  failure next to letting a producer build past a P the fleet agreed.
- **`--dry-run` applies to degraded mode.** The command-line flag (or
  `dry_run` in a config that parses) makes it log what it would pause and send
  nothing. A config that does not parse cannot say it asked for a dry run, so
  only the flag counts then.

## Follow-up to the unpatched eb5f1ffb rehearsal

The next cutover release supports protocol v3 in normal builds. Schedule
`{"protocol_upgrades":[{"protocol_version":3,"activation_height":H_PLUS_ONE}]}`
with the numeric H+1 substituted, identically on every validator. V2 enables
WASM start sections; it does not fix CPU units. The v3 boundary tests now run in
normal builds too. Never add a retroactive activation at H or below.

The restore gate rejects a successor transaction-signing ID equal to the source
ID, even with a correctly signed confirmation. The offline verifier makes the
same check when genesis pins the signing ID or the platform ID is supplied.
Both ceremony and launcher use `scripts/lib/migration-genesis.sh` so their
checkpoint, schedule, key and signing-ID fields cannot drift independently.

The builder can emit an empty block after five seconds without a block; the
normal-operation timer requests one every five seconds. The actual accepted
block timestamp stays the source of `head_block_time`. This refreshes client
expiry anchors after idle periods. Empty blocks run onblock and consume history
storage; their cadence is a local production policy, not a new validation rule.

For a continuous-history provider configure `history_provider=true`,
`block_production_enabled=false`, `state_sync_enabled=false`, and
`state_history_enabled=true`, with no producer key. Use the same canonical
`producer_name` as the validators (for XPR migration, `eosio`): it seeds the
initial verification schedule even when production is disabled, so any other
name makes the node refuse its first block with `block producer <name> is not
in the active schedule` — a symptom of a misconfigured `producer_name`, not a
corrupt checkpoint or a schedule problem on the chain itself. The explicit
provider role rejects settings that would state-sync away its history.
SHiP requests below retained history receive a policy-close response; inspect
`get_status` ranges and select the archive endpoint rather than waiting forever.
The served ABI now matches the 145-byte global_property envelope.

This release also validates WebAuthn keys in native newaccount authorities
against WEBAUTHN_KEY, matching the permission-update requirement. This tightens
native action validity, so deploy the release across all validators together
before the cutover. Do not mix it with older validators on an active chain.

The checkpoint and manifest are still startup dependencies, checked on every
restart, not only the first. This is intended: a node that lost its checkpoint
file, or whose file was swapped for a different one, must fail closed on the
next restart rather than keep running silently on whatever state it already
has. The cost is permanent: every node retains the (potentially large)
checkpoint and manifest at their configured paths forever, including long
after the migration is history. Do not remove them as part of cleanup.
Remove the retired `dead_chain_shutdown_after_secs` setting from old chain
configs before upgrading. No dead-chain shutdown guarantee is provided by
that removed setting.

The restore gate and empty-block changes do **not** establish tolerance of a
silent validator. MetalGo computes the benching cap as
`(1 - alpha_confidence / k) / 3`. With the reported settings that is 8.33%; one
of five equal validators has 20% and cannot be benched. One of 21 equal
validators has about 4.76%. Record the actual subnet parameters and weights,
then rehearse a silent validator, a syncing validator, and a plugin startup
refusal at 21-validator-equivalent weights. Require continued inclusions and
measure poll failures, benching and rejoin time. That remains a release gate.

A new declaration alone cannot release the prior round's persisted pause.
Use the coordinated reset procedure above after explicitly abandoning that
round; resuming XPR automatically after A-Chain writes would discard value.
CONFIRMED is a named operator decision after the observation checks. Even
before CONFIRMED, user-visible A-Chain writes require reconciliation before any
return to XPR. After CONFIRMED, remove participating operators' XPR keys under
the custody policy; other parties may still extend XPR.

State summaries now commit to a Merkle root over chunk-aligned leaves
(`chunk_merkle` in `state_sync.rs`), and a downloading node authenticates each
chunk against it as it arrives instead of only the whole file at the end: a
damaged or malicious chunk fails at that chunk, not after downloading
everything after it. This bumps the authenticated summary magic (`PVMSUM02` to
`PVMSUM03`): every node in a sync exchange needs the new binary, the same
coordinated-release requirement as a protocol feature. There is no fallback to
whole-file-only checking for a mismatched pair; they simply cannot sync with
each other until both are upgraded.

Remaining evidence and work: the native API conformance report (279 differences)
must be supplied before individual differences can be classified; the real
frozen pre-cut index and mainnet provider sizes remain untested. Real passkeys,
Anchor, Ledger, cleos, post-LIVE msig execution and the 21-producer availability
run remain integration gates. The box soak is evidence for eb5f1ffb, not for the
changes listed in this section.
