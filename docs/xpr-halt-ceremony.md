# XPR Cutover Ceremony: Two-Step Commit

One cutover, one terminal height H, one declaration, one confirmation.
The old schedule commits to H while H is still in the future (step one),
then binds the terminal block, the checkpoint, and the successor chain
(step two). The A-Chain verifies the full proof before producing H+1.

The proof is mandatory, not advisory: the restore gate refuses any
migration checkpoint whose manifest lacks the declaration +
confirmation pair, and rejects roster-less (single-key) commitments
everywhere. Timing must be provable — on-chain ceremony votes or a
recorded declaration inclusion — never merely asserted.

## Why two steps (forced by causality, not preference)

At H-K the state at H does not exist yet, so no one can sign it. At H the
pre-commitment window is gone. One signature cannot do both jobs:

- `M_decl = sha256("DECL" || C || H || S)` — signable at H-K (everything in
  it exists: source chain id, terminal height, full ordered validator set).
- `M_conf = sha256("CONF" || decl_digest || H || H_ID || S_H || N)` —
  signable only at H (needs the terminal block id and the state hash).

Two digests is the minimum. Time forces it.

## Who signs, with what

The block producers, with their **block-signing keys** — the same keys
that authorize XPR blocks. No ceremony keys, no new distribution. Because
S is inside the digested message, a signature over `M_decl` simultaneously
commits to (C, H) and endorses exactly that set S.

Each signer recomputes the digest from the *fields*, never trusting a
coordinator's bytes. BPs verify-then-sign as operational duty — in
particular they independently export the snapshot at H and derive N from
the public genesis recipe before signing the confirmation.

## The voting window (timing is consensus, not assertion)

Votes are XPR transactions, so their inclusion height *is* XPR consensus —
unlike off-chain signature timestamps, which are merely asserted. A
commitment is only valid inside its window:

- **Declaration votes: [H−K, H−1].** Strictly before H: H stays empty and
  the commitment is a genuine pre-commitment. The floor K is the freshness
  bound — ancient pre-signatures don't count, and K gives BPs real lead
  (votes land like H−J, well before the edge, not at H−1).
- **Confirmation votes: [H+1, H+J].** Strictly after H: a confirmation
  references H_ID, which cannot exist inside H itself (the block would have
  to commit to its own id). J bounds liveness — a ceremony that can't
  confirm within J blocks restarts.

Both bounds are enforced twice: the record step rejects out-of-window
votes at attach time, and the A-Chain enforces exact inclusion heights from
replay (restore gate) and offline (offline verifier). The declaration
side must prove its timing one of two ways — on-chain ceremony votes,
or a recorded declaration inclusion (memo / msig execution block); a
pair with neither fails closed. The confirmation side has no such
requirement (it is inherently post-H): when its inclusion is unrecorded
the verifier says so in the output, so "timing not provable" is never
silent there.

## Flip condition (gated, not implied)

The A-Chain starts producing H+1 only when **tip == H AND the confirmation
is finalized and verified**. Reaching H is not sufficient. If the
confirmation never completes, the chain halts safely instead of flipping
unverified. The rehearsal enforces this as an explicit pre-boot gate (a
verification-pass marker the boot refuses to proceed without), not just
phase ordering.

## The tally (proving the *set* committed)

Per signature, in order: parse the claimed key → `recover(digest)` must
equal it (forgery dies) → key must be in declared S, exact match
(outsiders die) → dedupe (re-signing adds nothing). Then:

- Numerator: sum of signer weights. Denominator: sum of the **full
  schedule's** weights from independently replayed XPR state — never from
  the declaration (a self-reported denominator is a self-graded quorum).
- Threshold: `signed x 3 > total x 2`, integer math. Strictly greater —
  exactly-two-thirds fails. That's the +1 in 2/3+1.

Weights are pinned to on-chain state at H by the schedule match below,
so the quorum is graded against reality, not against the signers' claims.
Weights are u128 truncated from `total_votes` — mainnet magnitudes
(~1e20+) saturate u64, silently turning a stake quorum into a member
count — and JSON carries them as decimal strings; the contract and the
verifier use the identical conversion so tallies agree bit-for-bit.

## The light-client rule (trust anchor)

The A-Chain replays XPR with full validation, so it independently knows
the schedule, every block id, and the full state at every height. The
declared set must **equal** the replayed schedule — names both ways,
keys, weights. This single check closes the subset attack (a declaration
naming only its signer verifies against itself but cannot match the
on-chain schedule it did not author) and the weight-inflation attack.
Vote or schedule drift between H-K and H fails closed and restarts
governance — same as a schedule change. One cutover means there is no
retry path: a failed ceremony is a new governance decision, not an
automatic round.

## Vehicles (transport, not proof)

The proof is the 7-check verification (well-formed S; S == replayed
schedule; 2/3 over `M_decl`; pre-commitment inclusion at height < H; 2/3
over `M_conf`; H_ID and S_H match replay; N == self). Any vehicle that
delivers the proof bytes is compliant. In order of preference:

1. **`eosio.msig` executed proposal** (if deployed on XPR): zero new code,
   most-audited contract, approvals public/ordered/timestamped, proposal
   bytes carry the full declaration. The executed proposal with 2/3+
   producer approvals *is* the commitment.
2. **Dedicated `cutover` contract** (built, fixture-proven):
   `init(H, source_chain_id)` freezes the **live `eosio.producers` table**
   in-contract — the set is read from chain state, never supplied by a
   caller — keeping only active rows, enforcing 1-of-1 single-key
   authorities whose key equals the schedule key, and computing the
   declaration digest over the frozen roster. `vote(producer, sig)`
   recovers the block-signing key over that digest, checks membership in
   the frozen set, rejects doubles, and adds the member's frozen weight;
   `voted * 3 > total * 2` finalizes and locks the freeze (re-init is
   allowed only before the first vote). Weights are u128 (mainnet
   `total_votes` saturates u64); the digest is byte-identical to the
   off-chain declaration, so one BP signature serves both tallies. The
   relay is permissionless — the signature inside the action is the
   authorization — so any party can submit votes; outsiders, wrong-height
   digests, doubles, and post-finalize votes all fail in-contract.
3. **Memo vehicle** (rehearsal): the declaration digest encoded on-chain;
   the set travels off-chain and is validated against replayed state.
   Proves the crypto and the sequence with zero deployment.

`declaration.json` is byte-identical to the contract row / proposal
content across all three — only the transport changes.

## Signing automation (the auto-voter)

BPs sign with the block-signing key either way; the question is only how
the signature gets made. `xpr_cutover_voter` (example binary, live-tested
against a throwaway node) polls the ceremony tables and signs for the
operator once the frozen set matches the coordinated parameters:

- Refuses anything but the exact freeze: wrong height, wrong source
  chain, a digest that does not recompute locally, keys outside the frozen
  set, double votes, and votes at or after H. Every refusal is logged.
- Keys come from owner-only files, never the command line, and are never
  logged. `--dry-run` evaluates and logs every decision without signing.
- After H is final it signs the confirmation and delivers it to the
  coordinator (whose block id and checkpoint are cross-checked against
  the local node and config) or writes it to a file.
- The vote it submits is byte-identical to the manual `cvote` path, so
  automated and manual fleets verify together
  (`contracts/cutover/test-voter.sh`: dry-run refusal, unattended live
  vote, coordinator delivery, lying-coordinator refusal).

What automation cannot do is decide: H, the source chain, and the roster
come from the coordinated config, and a failed ceremony restarts
governance, not the loop. See `tools/xpr-cutover-voter/` for the example
config and systemd unit.

## Contract evidence (what the exporter attaches)

With the contract vehicle the declaration signatures *are* the on-chain
votes, so timing is provable per vote instead of per quorum. The exporter
(`xpr_scan_contract_votes`) scans the window for `cutover::vote` actions,
unpacking each action's `(producer, SIG_K1_)` and resolving the key from
the frozen members table, and captures the `ceremony` singleton
(`finalized`, digest, tally). The fragment lands in the manifest as
`halt_contract_ceremony`, and the verifier replays it off-chain: singleton
finalized on the verified declaration digest, every vote a rostered
schedule key inside the declaration window, captured tally equal to the
recomputed signer weight, strict quorum on the recomputation. The
confirmation still chains declaration → terminal block → checkpoint →
successor chain id; the contract evidence replaces only the inclusion
block, never the checks.

One deployment gotcha the fixture proved: Leap `setabi` carries the
*packed binary* `abi_def`, not the JSON text (`cleos` packs client-side).
Submitting raw JSON executes but leaves nothing `get_abi` or
`get_table_rows` can unpack. The probe tool packs for cleos parity.

## What XPR verifies vs what the A-Chain verifies

XPR consensus verifies what it knows: auth, recovery, tally,
finalization. The A-Chain re-verifies all of it (never trusts the
finalized flag — a buggy contract could finalize at 1/3) plus what XPR
cannot know: `S_H` correctness, `N` correctness, `H_ID` from its own
replay. Each chain verifies what only it can know; everything is
recomputed at the destination.

## After the flip

H and H+1 linkage lives in A-Chain blocks (`previous == H_ID`). The proof
is historical from there — archived with the migration genesis, not
re-verified per block. There is no reverse migration and no coexistence:
XPR is abandoned at H, so every gate fails closed before H+1.
