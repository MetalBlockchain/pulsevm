# XPR Cutover Handoff: Mechanism, Proof Rules, Verification

One cutover, one terminal height H, one declaration, one confirmation.
The old validator set commits on-chain to stop at H; the A-Chain verifies
that commitment against the old schedule's keys before producing H+1.
This document is the handoff record: what the mechanism guarantees, what
the restore gate enforces, what was verified, and what mainnet still needs.

Design detail lives in [xpr-halt-ceremony.md](./xpr-halt-ceremony.md);
rehearsal operations in [xpr-handover-rehearsal.md](./xpr-handover-rehearsal.md);
the full migration plan in [xpr-achain-migration.md](./xpr-achain-migration.md).
The code is authoritative where they disagree.

## 1. What the old set signs, and why two steps

Causality forces two digests: at H-K the terminal state does not exist yet,
at H the pre-commit window is gone. One signature cannot do both jobs.

- Step one, signable at H-K: `M_decl = sha256("DECL" || C || H || S)` —
  source chain id, terminal height, full ordered validator set (names,
  block-signing keys, weights).
- Step two, signable only at H: `M_conf = sha256("CONF" || decl_digest ||
  H || H_ID || S_H || N)` — chains the declaration to the terminal block
  id, the checkpoint hash, and the successor chain id.

Signers are the block producers with their block-signing keys. No ceremony
keys, no new distribution. Each BP recomputes the digests from the fields
and independently exports the snapshot before signing the confirmation.

## 2. Proof rules the restore gate enforces

A migration checkpoint restores **only** with the full pair, verified
against independently replayed XPR state:

1. **Pair mandatory.** No declaration + confirmation, no restore. A manifest
   with neither fails closed at the gate.
2. **Schedule quorum, strict 2/3+1.** Every signature is K1-recovered and
   must equal a rostered key; each key counts once; `signed x 3 > total x 2`
   in u128 integer math. Roster-less (single-key) commitments are rejected
   everywhere — one key cannot prove the schedule agreed.
3. **Roster provenance.** The set is frozen on-chain from the live
   `eosio.producers` table (never prover-supplied; multisig schedules fail
   closed), and the gate cross-checks names, keys, *and* weights against the
   checkpoint's own producers table — the light-client rule: same set both
   ways.
4. **Pre-commitment timing provable.** Declaration votes must land before H,
   proven one of two ways: on-chain ceremony votes (contract vehicle), or a
   recorded declaration inclusion (memo / msig execution block). A pair with
   neither fails closed — off-chain signatures alone say nothing about when
   they were made.
5. **Freeze window, no bricking.** Votes land within seven days of the
   freeze (`init_time`, XPR consensus time); afterwards the freeze expires:
   votes are refused and anyone may re-init, votes or not. A wrong-H or
   abandoned freeze can never lock the contract — expiry is the escape
   hatch, and there is no admin to call instead. The voter refuses expired
   freezes rather than submitting doomed votes.
6. **Roster shape.** Every active producer must be plain 1-of-1 K1 with
   its authority key equal to its schedule key; anything else (multisig,
   non-K1, mismatched keys) fails init closed. Audit with
   `contracts/cutover/check-schedule-readiness.py` at T-14 and at freeze
   time — a single bad row dooms the ceremony before it starts.
7. **Bindings.** Confirmation ties H, block id, checkpoint, and successor
   chain id to the declaration; the checkpoint hash is recomputed from the
   artifact, never trusted as a string. Replay across heights, exports, or
   chains cannot verify.

## 3. Verification evidence

- Unit + gate tests: 317 `pulsevm_core`, 109 `pulsevm_database`, 6 offline
  verifier tests — including rejection of pair-less manifests, roster-less
  commitments, tampered signatures, quorum shortfall, checkpoint mismatch,
  late votes, inflated tallies, and unreadable timing. The SHiP log read
  path carries a regression test proving reads observe unflushed deferred
  appends (a follow-mode tail-read failure found by the rehearsal).
- Contract fixture (`contracts/cutover/test-local.sh`): 14/14 — outsider
  rejection, wrong-height votes, double votes, strict-quorum boundary
  (finalizes only past 2/3), locked freeze, vote scan reproducing the tally.
- Full rehearsal PASS at H=163 (fresh chain, default two-step memo path):
  declared at memo block 137 (K=26), offline pair verification green, flip
  gate opened, H+1=164 parent-linked to H_ID, state equivalence 11/11
  accounts, boundary traffic 10/10 exactly-once.

## 4. What mainnet still needs (inputs)

- **Validator coordination.** BPs run the ceremony: freeze the contract (or
  record the memo) inside the window, sign the declaration before H, sign
  the confirmation once H exists. One governance decision, one window. A
  failed freeze is re-taken, not escalated: re-init while voteless, or any
  time after the 7-day window expires. Only a wrong coordinated H needs a
  new governance decision.
- **Schedule stability.** A schedule rotation between the freeze and H fails
  closed (roster no longer matches state) and restarts the ceremony. Freeze
  close to H.
- **Gateways and RPC.** JSON-RPC/HTTPS endpoints, exchanges, and indexers
  cut over at H+1 to the A-Chain; XPR endpoints are abandoned at H with no
  coexistence period. Coordinate the switch per client, not per block.
- **XPR is abandoned, not halted.** No protocol change stops XPR: upgraded
  nodes pause their own block production after delivering the confirmation,
  and everyone else follows the A-Chain. If a third or more of stake
  upgrades, XPR stalls organically near H (the clean stop, for free). If
  fewer upgrade, XPR keeps producing an unfollowed minority fork — visible
  on explorers, meaningless for the cutover. Do not present this as a chain
  halt to operators; present it as a coordinated move with a dead
  origin chain.
- **History.** The A-Chain serves blocks from H+1; pre-H history stays on
  XPR archive nodes and the exported SHiP logs. There is no transaction
  lookup index on the new chain until one is built — plan explorer coverage
  accordingly.

## 5. Files

- Ceremony contract: `contracts/cutover/cutover.cpp`
- Proof types + quorum math: `crates/pulsevm_chain_types/src/migration.rs`
- Restore gate: `crates/pulsevm_core/src/chain/controller.rs` (migration
  section of `initialize`)
- Manifest + verifier: `crates/pulsevm_database/src/xpr_import.rs`,
  `crates/pulsevm_database/examples/xpr_verify_manifest.rs`
- Rehearsal: `docker/handover/run-handover.sh`
