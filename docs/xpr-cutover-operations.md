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
| Voter config per producer (producer name, keys, producer API URL) | Each BP | `--preflight` must print GO before the freeze |
| Schedule readiness: `check-schedule-readiness.py` PASS | Chain ops | Every active producer 1-of-1 K1, keys match schedule, no pending rotation; a single bad row dooms init |

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
   `stop_producer` armed, each producer pauses after delivering its
   confirmation. Post-H stragglers are expected and ignored — the new
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
