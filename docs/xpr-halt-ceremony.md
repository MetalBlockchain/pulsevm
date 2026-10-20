# XPR Validator Halt Commitment: On-Chain Vote Strategy

Status: strategy; the quorum verifier is **implemented and tested**
(`HaltCommitment::verify_weighted_quorum` + 9 boundary tests, see
“Implementation status”). Decided: validators commit **on XPR itself**,
quorum is **2/3 of producer-schedule weight**. Companion docs:
[rehearsal proof](xpr-handover-rehearsal.md), full migration design
([`xpr-achain-migration.md`](xpr-achain-migration.md)).

## Why on-chain

The rehearsal's halt commitment is signed off-chain by one key and baked into
the manifest by the exporter — the new chain verifies the crypto but trusts
the exporter for *who may sign*. An on-chain vote removes that trust: every
validator's commitment is a public, timestamped XPR transaction, replayed by
the shadow like any other state, so the A-Chain derives the roster and the
quorum from its own replayed state instead of trusting exported claims.

## Two phases (block id is unknowable in advance)

**Phase A — lock H (pre-halt).** A commit contract accepts
`commit(producer, halt_height)` with `require_auth(producer)`. Each scheduled
producer votes the terminal height it will stop at. Once votes for one height
reach 2/3 of schedule weight, that H is locked; the contract rejects other
heights. If quorum is never reached, nothing locks and the chain keeps
running — the safe default is no migration.

**Phase B — attest the id (post-halt, pre-promotion).** After producers stop
at locked H, each attests `attest(producer, halt_height, halt_block_id,
signature)` where `signature` is the producer's K1 signature over the same
canonical message the manifest uses today (`PULSEVM-XPR-HALT-v1 || height ||
block-id`). The contract recovers the key (`assert_recover_key`), checks
schedule membership, and counts weight. At 2/3, the halt is fully committed.

## Weight and roster (no oracle)

- Roster: the active producer schedule at a finalized reference block R
  (derivable exactly — the replay has every block header).
- Weight per producer: `total_votes` from the `eosio.system` producers table
  at R. Threshold: weight(H-votes) ≥ 2/3 of roster weight.
- The A-Chain recomputes roster and weights from its **own replayed state**
  and re-checks the on-chain votes; the manifest exporter only transports
  bytes, it is not trusted for membership or arithmetic.

## What the contract cannot do

It cannot halt the chain — BPs still stop nodeos by coordinated action, and
the freeze is proven the way the rehearsal proves it (snapshot head, halt,
block-log stillness). The contract provides the *commitment*: public,
countable, and replayable. Enforcement stays where it is today, on the new
side: restore fails closed unless the on-chain quorum verifies.

## Failure handling

- **Quorum never reached:** no lock, no halt, chain continues. Re-vote later.
- **Halt misses locked H** (straggler blocks past H): the id attestation will
  not match the locked height's canonical chain; promotion refuses. Re-vote a
  new H — votes are single-use per height.
- **Key compromise / producer change mid-ceremony:** roster is pinned at R;
  a schedule change after R starts a new ceremony with a new R.
- **Replay divergence:** votes are ordinary actions, so any shadow that
  disagrees about the vote set disagrees about state — caught by the existing
  state-equivalence gate before promotion is even considered.

## Implementation status

- [x] Quorum verifier: `HaltCommitment::verify_weighted_quorum` in
  `crates/pulsevm_chain_types/src/migration.rs` — schedule membership, K1
  recovery per signature, one-weight-per-producer dedupe, integer
  `signed*3 >= total*2` threshold, fail-closed empty/zero rosters; 9
  boundary tests (exact quorum, shortfall, double-sign, non-roster,
  tampered terminal/version) plus v1-compat test.
- [ ] Commit contract (`haltcommit`): tables `roster` (pinned at R), `votes`,
  `attests`; actions `setroster` (privileged, once), `commit`, `attest`;
  unit tests against a local schedule.
- [x] Exporter: `xpr_attach_source_block --halt-roster <roster.json>`
  attaches the weighted roster (manifest version 2); `--halt-key-v2` signs
  a checkpoint-bound version 2 commitment. v1 single-key path stays valid.
- [x] Restore path: the `halt_commitment` restore gate in `controller.rs`
  verifies the weighted quorum when the manifest carries a roster (v1 and
  v2 commitments) and the checkpoint binding for version 2; fail closed.
- [x] Roster-to-state binding: after restore, every rostered name must
  resolve to the same signing key in the checkpoint's own `producers`
  table (`migration_state_producer_keys` + `check_halt_roster_against_state`
  in `xpr_import.rs`). Weights and `is_active` are not cross-checked —
  both legitimately drift between the roster reference and the checkpoint —
  so full R-pinned weight semantics still belong to the on-chain ceremony.
- [ ] Rehearsal: distinct per-validator keys, scripted Phase A + B, negative
  test (quorum shortfall refuses promotion).
