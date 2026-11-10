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
| Successor chain id, or the pinned `chain_id` (U-1) | Chain ops + MetalGo team | Without U-1: published at H, wallets flip at H+ε |
| Platform chain id | MetalGo team | Bound into every confirmation; the gate refuses without it |
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

**Superseded round.** If H+1 slips in before the pause (snapshot holds a
head past H), the round is dead: the old declaration stays on-chain as
superseded history and the ceremony restarts at a new H. Never reuse an
H, never confirm a superseded digest, never hand-edit a manifest to fit.

**No-go conditions (any one restarts governance, not the loop):**
schedule change staged mid-window, frozen digest mismatch, coordinator
data disagreeing with the local node, tally short of 2/3 at H, or a
confirmation that will not verify. A failed ceremony is a new governance
decision, not a same-H retry.

## Platform chain id ordering (testnet and mainnet)

The platform id (MetalGo blockchain id) is a hash of the CreateChain
transaction, whose genesis commits to the checkpoint hash. Both exist only
after H is exported, so the id cannot be published at T-14 and cannot be
pinned by U-1 (`chain_id_override` only names the PulseVM chain id for
wallets). The real order is therefore the one the rehearsal harness calls
learn-then-bind:

1. After H: export the checkpoint, build the migration genesis, register the
   chain on the MetalGo subnet. The first boot refuses at the restore gate
   (no confirmation binds this platform id yet) and serves no RPC.
2. Chain ops publishes the registered platform id; each BP confirms against
   it (the coordinator cross-checks the id against the local node).
3. A-Chain nodes restart with the confirmation set and pass the gate.

Plan the confirmation window (H..H+J) to include steps 1-2 end to end, and
do not treat the step-1 refusal as an incident. A refusal for any other
reason is a stop-and-diagnose.

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
The exit code is 3 and the log carries an `ALARM event=cutover.schedule_pin_abort`
line: page on either. There is no on-chain abort, so a bump between
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
compares (`redenominate_source_tables`) for `global_property`,
`resource_limits_config`, `resource_limits_state` and `resource_usage`, and
prints a line saying so; every other byte and table is still compared exactly.

The factor is a ratio of block caps, not a measurement of cost per microsecond.
Whether that makes a typical XPR account's allowance buy the same real work is
an open calibration question that needs the mainnet replay: measure billed
points per source microsecond across real traffic and compare it with the
factor. An account whose whole allowance is below the 100,000-point minimum
bill cannot transact; that is about 7 us of XPR-equivalent allowance, below
XPR's own 100 us minimum bill, so nobody who could transact on XPR is locked
out by the minimum alone.

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
