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
  block-signing keys, unit weights).
- Step two, signable only at H: `M_conf = sha256("CONF-v2" || decl_digest ||
  H || H_ID || S_H || N || P)` — chains the declaration to the terminal
  block id, the checkpoint hash, the successor chain id, and the mandatory
  platform id wallets sign under.

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
   in u128 integer math — a count quorum over unit members (15 of 21 on
   mainnet), never a vote-weight fraction. Roster-less (single-key)
   commitments are rejected everywhere — one key cannot prove the schedule
   agreed. Exactly-two-thirds fails everywhere, including the legacy
   commitment path.
3. **Roster provenance.** The set is the frozen **active schedule** (names,
   schedule keys, version): one member, one vote. The contract freeze takes
   the schedule explicitly and gates every key to K1; the gate anchors each
   member to checkpoint state (active, same key) and pins the attested
   version to H's header version. Vote weight is gone — no denominator to
   drift, no standby can brick the freeze.
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
6. **Roster shape.** The roster freezes the live schedule keys, each
   gated to valid K1 at init; a non-K1 schedule key fails the freeze
   instead of minting an entry nobody can sign for. XPR producers rows
   carry no authority field (verified against live mainnet rows: 8
   fields, 90 bytes), so there is nothing multisig to audit in the
   roster path — DPoS schedules hold single keys by protocol, and votes
   are K1 recoveries against the frozen schedule keys, never permission
   checks. Audit with `contracts/cutover/check-schedule-readiness.py`
   at T-14 and at freeze time: valid K1 schedule keys, producers-table
   keys equal to the schedule signing keys, no staged schedule rotation —
   a single bad row dooms the ceremony before BPs spend signatures on
   it. The restore additionally requires the export-time attestation that
   the checkpoint carries no proposed schedule (hydration keeps only the
   parsed chain config, so absence cannot be re-derived later).
7. **Bindings.** Version-2 confirmation ties H, block id, checkpoint,
   successor chain id, **and the mandatory platform id** to the
   declaration; the checkpoint hash is recomputed from the artifact, never
   trusted as a string. Replay across heights, exports, or chains cannot
   verify.

## 3. Verification evidence

- Unit + gate tests: workspace green (counts move with the suite — verify
  with `cargo test --workspace --locked`) — `pulsevm_core` lib,
  `pulsevm_database` lib, `pulsevm_chain_types`, 25 voter
  example (including Leap-4/5 authority parsing: tags 0 and 1 parse;
  flat-key, threshold-2, multi-key, and unknown-tag shapes refuse), 9
  offline verifier example — including
  rejection of pair-less manifests, roster-less commitments, non-unit
  transported weights, duplicate declaration members, tampered
  signatures, exact-2/3 quorums (legacy path included), quorum
  shortfall, checkpoint mismatch, stale schedule versions,
  proposed-schedule checkpoints, late votes, inflated tallies, unreadable
  timing, pause-headless legacy confirmations, post-H proofs that stop
  short of or run past the attested pause head, deferred rows due in the
  pause window, table-less checkpoints with a valid pair, and
  confirmation-time schedule drift or staging; plus the determinism
  proof that two independent conversions of one export give byte-identical
  checkpoints. The attach side carries `migration_attach` lib tests: schedule pin
  (version match, unit weights, duplicate/bad-key/empty/pinned-conflict
  rejection) and post-H recording (broken linkage, traffic, rotation,
  unknown producer, forged key, non-K1 signature, missing schedule,
  wrong blockroot, foreign schedule hash, missing state fields,
  block/state count skew, foreign block id) with a round-trip of the
  recorded proof through the real restore gate — over Leap's true
  producer signature digest (the exact root/hash pair bound by recovery)
  and the verbatim carried block ids. The SHiP
  log read path carries a regression test proving reads observe unflushed
  deferred appends (a follow-mode tail-read failure found by the
  rehearsal). Database-stack clippy clean; pinned-nightly fmt clean.
- Contract fixture (`contracts/cutover/test-local.sh`, 4-member count
  quorum: 1 and 2 of 4 must not finalize, 3 of 4 must) and scale fixture
  (`contracts/cutover/test-scale.sh`, 21 members: 15 of 21) — outsider
  rejection, wrong-height votes, double votes, exact-half non-finalization,
  locked freeze, vote scan reproducing the tally. Fixture scripts validate
  with `bash -n` and embedded-Python compile checks here; they execute
  against a Leap fixture node in rehearsal/CI.
- Full rehearsal PASS at H=340 (fresh chain, default two-step memo path
  over the new proof bytes): declared at memo block 311 (K=29), offline
  pair verification green, flip gate opened, H+1=341 parent-linked to H_ID,
  state equivalence 11/11 accounts, boundary traffic 10/10 exactly-once —
  see [xpr-handover-rehearsal.md](./xpr-handover-rehearsal.md). That run
  proves the true-digest record (header-state staged per post-H header),
  the verbatim carried ids, the seed-planted producers table (boot gate
  reports the roster match; a table-less checkpoint fails closed at the
  same gate), the learn-then-bind platform re-issue, and the live finding
  that an empty pending schedule is the norm (no hash-to-roster comparison
  is attempted — a wrong pin failed an earlier run of the same rehearsal
  live and was removed).

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
- Attach-side schedule/post-H recording (lib + tool):
  `crates/pulsevm_core/src/migration_attach.rs`,
  `crates/pulsevm_core/examples/xpr_attach_source_block.rs`
- Rehearsal: `docker/handover/run-handover.sh`
