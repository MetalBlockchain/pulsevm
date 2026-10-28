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
- `M_conf = sha256("CONF" || decl_digest || H || P || H_ID || S_H || N || PLAT)` —
  signable only at H (needs the terminal block id and the state hash).
  `P` is the highest pause head the quorum observed frozen; every
  confirmer signs the same unanimous `P` (a frozen network observes one
  head — disagreement means the network is not frozen and refuses). The
  post-H emptiness proof must cover exactly H+1 through `P`, so a proof
  that stops short of the quorum's own observation fails the boot closed.
  `PLAT` is the MetalGo blockchain id wallets sign under, bound
  positionally and mandatorily.

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

- Numerator: signer count. Denominator: the declared set's size. The
  declaration carries the roster, and the light-client cross-check below
  pins that roster to the frozen schedule — never trusted on its own
  (a self-reported denominator is a self-graded quorum, so the roster is
  verified, not assumed).
- Threshold: `signed x 3 > total x 2`, integer math. Strictly greater —
  exactly-two-thirds fails. That's the +1 in 2/3+1.

Every member weighs exactly 1: the quorum is a **count quorum** over the
frozen active schedule (names, schedule keys, version), matching Leap
irreversibility exactly — 15 of 21, never a vote-weight fraction. Vote
weight (`total_votes`) tracking is gone: it drifted every block, let a
handful of large producers clear quorum alone, and let standby churn
brick the freeze. Standbys are simply not in the quorum whether or not
they are active. The singleton's totals are member counts, not weights;
the memo path tallies the same count quorum without a frozen singleton.
Weights stay on the wire as decimal-string `1`s so digests keep their
shape; anything else fails closed at declaration parse.

## The light-client rule (trust anchor)

The A-Chain replays XPR with full validation, so it independently knows
the schedule, every block id, and the full state at every height. The
declared set must **equal the checkpoint's active producer set exactly,
both ways, with matching schedule keys**. The forward direction is
key-for-key anchoring that closes the gap where
`producers.producer_key` can differ from the schedule's signing key. The
reverse direction closes the standby-subset attack: without it, three
active standbys could declare themselves as the roster, record the same
three as the schedule, and pass 3-of-3 over a quorum whose denominator
they chose. The checkpoint (bound by the confirmation's checkpoint sha)
is the only authenticated roster, so the version pin and the count quorum
— necessary but not sufficient, since a subset copies H's version and
picks its own denominator — cannot substitute for it. Member or key drift
between H-K and H fails closed and restarts governance — same as a
schedule change. One cutover means there is no retry path: a failed
ceremony is a new governance decision, not an automatic round.

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
   `init(H, source_chain_id, schedule_version, schedule)` freezes the
   **coordinated active schedule** — names, schedule keys, version — one
   member, one vote, no vote weights anywhere. The set is supplied by the
   coordinator (the chain exposes no schedule table to contracts), keyed
   to K1, unique, and sorted into the declaration digest, which is
   byte-identical to the off-chain declaration, so one BP signature
   serves both tallies. `vote(producer, sig)` recovers the block-signing
   key over that digest, checks membership in the frozen set, rejects
   doubles, and adds one; `voted * 3 > total * 2` finalizes. Re-init is
   allowed while voteless, or once the 7-day freeze window expires —
   even with votes on it — so an abandoned freeze can never brick the
   contract. The relay is permissionless — the signature inside the
   action is the authorization — so any party can submit votes;
   outsiders, wrong-height digests, doubles, and post-finalize votes all
   fail in-contract.
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
  set, double votes, votes at or after H, a schedule version that is not
  the coordinated one (frozen, live, and config must agree all three
  ways), a staged producer schedule change (pending/proposed), and a
  frozen set that no longer matches the live active schedule (member or
  schedule-key drift since the freeze): a freeze taken under a rotating
  or stale set signs nothing. Every refusal is logged.
- Re-checks the schedule at confirmation time, not just at declaration
  time: the voter re-reads the live schedule before signing the
  confirmation and refuses on a staged change (pending or proposed), a
  version mismatch, or member/key drift — so a rotation between the vote
  and H+1 attests nothing. The confirmation carries the voter's own
  observed pause head into the coordinator, where the highest attested
  head becomes the `P` the proof must cover.
- Keys come from owner-only files, never the command line, and are never
  logged. `--dry-run` evaluates and logs every decision without signing.
- `--print-digest` prints the currently actionable signing digest as JSON
  and exits without signing: an external agent (or remote signer) signs
  exactly those bytes with its own key management and submits through its
  own path, so key custody never moves. The digest equals the voter's own
  signing digest by construction (unit-tested, live-tested).
- After H is final it signs the confirmation and delivers it to the
  coordinator (whose block id, checkpoint, successor id, and platform id
  are cross-checked against the local node and config) or writes it to a
  file. The version-2 confirmation always binds the platform chain id;
  the field is mandatory and unbound evidence is rejected outright. The
  unsigned template is built by one shared library constructor, so the
  voter, the coordinator tool, and external `--print-digest` signers all
  sign the same bytes by construction.
- The vote it submits is byte-identical to the manual `cvote` path, so
  automated and manual fleets verify together
  (`contracts/cutover/test-voter.sh`: dry-run refusal, print-digest
  parity, unattended live vote, platform-bound coordinator delivery,
  lying-coordinator and wrong-platform refusal).
- Opt-in local halt: with `stop_producer.at_pause` set plus the local
  `producer_api_url`, the voter pauses its own producer once its
  confirmation for the agreed `pause_height` is delivered and the local
  head has reached P (Leap `producer/pause`, then proves `paused`) and
  keeps enforcing it. Every signer confirms the same agreed head P — a
  fixed H+k set before the freeze — never its own observed tip, so
  divergent voters cannot split the quorum digest; a coordinator
  publishing a different P is refused. Only a voter that delivered its
  own confirmation pauses, so an aborted ceremony never halts a live
  chain by accident: the fleet pact must therefore ensure every
  scheduled producer confirms. A contract cannot stop block production,
  only the producer can, so this is the half of the halt that lives in
  the binary. Off by default; half-configured (armed without a URL) or
  stale (`at_h`, which stopped at H) refuses to start; a pause that
  will not verify is retried in-loop and logged loudly instead of
  degrading to a warning. A node restart clears Leap's in-memory pause,
  which is why the voter re-asserts rather than pausing once and
  exiting. To resume production deliberately, stop the voter first: a
  manual resume while it runs gets re-paused on the next poll. Near H
  the loop polls every second so the pause lands promptly, then drops
  back to the configured cadence.

What automation cannot do is decide: H, the source chain, and the roster
come from the coordinated config, and a failed ceremony restarts
governance, not the loop. See `tools/xpr-cutover-voter/` for the example
config and systemd unit.

## Contract evidence (what the exporter attaches)

With the contract vehicle the declaration signatures *are* the on-chain
votes, so timing is provable per vote instead of per quorum. The exporter
(`xpr_scan_contract_votes`) scans the window for `cutover::vote` actions,
unpacking each action's `(producer, SIG_K1_)` and resolving the key from
the frozen members table, recording each vote's block header schedule
version, and captures the `ceremony` singleton (`finalized`, digest,
tally). The fragment lands in the manifest as `halt_contract_ceremony`,
and the verifier replays it off-chain: singleton finalized on the
verified declaration digest, every vote a rostered schedule key inside
the declaration window **and under H's schedule version** (a rotation
anywhere in the window fails closed), captured tally equal to the
recomputed signer count, strict quorum on the recomputation. The
version-2 confirmation still chains declaration → terminal block →
checkpoint → successor chain id **plus the mandatory platform (MetalGo
blockchain) id wallets sign under**; the contract evidence replaces only
the inclusion block, never the checks.

One deployment gotcha the fixture proved: Leap `setabi` carries the
*packed binary* `abi_def`, not the JSON text (`cleos` packs client-side).
Submitting raw JSON executes but leaves nothing `get_abi` or
`get_table_rows` can unpack. The probe tool packs for cleos parity.

## Post-H window (what the exporter stages)

The version pin does not stop at H. The rehearsal stages
`schedule-H.json` (the live `get_producer_schedule` at the freeze),
every header from H+1 to the pause head (`block-post-N.json`), and each
header's `get_block_header_state` (`block-post-N.state.json`), and the
attach tool records all three: the schedule at unit weight pinned to H's
header version, each post-H header hash-linked from the trusted H id
with an empty transaction root and signed by the recorded schedule key
for its producer. The state supplies the two signature inputs the
header cannot — the blockroot root and the pending schedule hash — so
the signature is re-verified over Leap's true digest
(`sha256(sha256(sha256(header) || root) || schedule_hash)`). The state's hash
is bound by the signature itself: only the exact (root, hash) pair Leap
signed recovers to the roster key, so there is no hash-to-roster
comparison to fool — and none is attempted, because with no staged
change Leap serves the EMPTY pending schedule, whose hash cannot equal
the active roster's (proven against live header states on the first
rehearsal run). `P` itself comes from the validators' own frozen-head
observations (recorded per signer, required to agree — the ceremony tool
refuses a split view of a supposedly frozen network) and is signed into
the step-two confirmation, so the coverage bound is quorum-attested, not
coordinator-typed. The restore gate re-verifies the packed proof,
requires the recorded schedule to equal the declared set exactly, and
requires the staged headers to cover exactly H+1 through the attested
`P`, so the 330-block confirmation window Paul flagged cannot hide
traffic the checkpoint is missing: a header carrying transactions, a
rotation, or a signature from outside the frozen set fails the export, a
proof that stops short of the quorum's own head fails the boot, and an
unstaged window fails the boot.

Capture ordering matters: Leap only serves `get_block_header_state` for
still-reversible blocks, while the freeze protocol requires the
validators' LIB to cover H (making H irreversible everywhere) before the
producer pauses. The rehearsal therefore captures H's pair in the same
poll iteration that first observes head == H (before snapshotting),
captures each H+1.. tip the moment it appears during the LIB wait, and
tops up only the fresh tip from a validator after the pause. Fetching any
pair after finality has passed fails closed and supersedes the round.

Prevention is procedural, verification is cryptographic. On the source
side, the fleet admission lock plus the edge freeze PREVENTS post-H
traffic: nothing new is admitted, and the validators stop building. On
our side, the staged proof VERIFIES the freeze held: the gate replays
every header H+1 through the highest attested pause head rather than
trusting the lock. The two halves belong to different parties — the fleet
operates the freeze, the A-Chain checks it — so a broken freeze cannot
strand users: the gate turns it into a refused boot, loudly, before H+1
is ever produced, instead of promoting state the schedule never endorsed.

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
