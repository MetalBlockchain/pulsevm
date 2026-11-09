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

- **Declaration votes: [H−K, H−1].** Strictly before H: the commitment
  is a genuine pre-commitment. H itself is an ordinary source-chain block
  and may carry traffic — the snapshot covers the state its transactions
  produced; only H+1..P must be empty. The floor K is the freshness
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
or the declaration memo accounts (names re-decoding to the digest,
checkpoint creation dates bound to the recorded slots); a
pair with neither fails closed. A bare recorded inclusion height
proves nothing by itself — the number is exporter-asserted — so it no
longer satisfies this requirement. The confirmation side has no such
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
- Only valid signatures count. A signature that is malformed, claims a key
  outside the declared set, or does not recover to its claimed key is
  skipped, not fatal: one bad entry (a buggy voter, a voter on another fork,
  a hostile insider) cannot veto a set that still carries a quorum, and adds
  nothing to a set that does not. A bundle with more signatures than members
  is refused before any recovery work is done.

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
  the coordinated one, and a frozen set that no longer matches the
  coordinated active schedule (member or schedule-key drift since the
  freeze): a freeze taken under a rotating or stale set signs nothing.
  Every refusal is logged.
- Re-checks the schedule at confirmation time, not just at declaration
  time: the voter re-reads the schedule before signing the confirmation
  and refuses on a staged change (pending or proposed), a version
  mismatch, or member/key drift — so a rotation between the vote and H+1
  attests nothing. The confirmation carries the ceremony's agreed pause
  head P — a fixed H+k set before the freeze — never the voter's own
  observed tip, so divergent voters cannot split the quorum digest; a
  coordinator publishing a different P is refused.
- Keys come from owner-only files, never the command line, and are never
  logged. `--dry-run` evaluates and logs every decision without signing.
- `--print-digest` prints the currently actionable signing digest as JSON
  and exits without signing: an external agent (or remote signer) signs
  exactly those bytes with its own key management and submits through its
  own path, so key custody never moves. The digest equals the voter's own
  signing digest by construction (unit-tested, live-tested).
- It signs the confirmation over the agreed P once the stop is locally
  observed (head at or past P) — no LIB wait: on a large
  committee LIB(H) arrives hundreds of blocks after the agreed stop, and
  the 15-of-21 confirmation quorum over H_ID stands in for Leap finality —
  and delivers it to the coordinator (whose block id, checkpoint,
  successor id, and platform id are cross-checked against the local node
  and config) or writes it to a file. The version-2 confirmation always
  binds the platform chain id;
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
  `producer_api_url`, the voter pauses its own producer once the local
  head has reached P (Leap `producer/pause`, then proves `paused`) and
  keeps enforcing it — whether or not its own confirmation was
  delivered, because a producer whose submission failed must still stop
  or its tail runs past the proof window unstaged. Every signer confirms
  the same agreed head P — a fixed H+k set before the freeze — never its
  own observed tip, so divergent voters cannot split the quorum digest; a
  coordinator publishing a different P is refused. A contract cannot stop
  block production, only the producer can, so this is the half of the
  halt that lives in the binary. Off by default; half-configured (armed
  without a URL) or
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

## Committee authentication (where the schedule comes from)

The committee the gate trusts is the one the **Leap snapshot of H** states,
not anything an exporter types or fetches. The snapshot's
`eosio::chain::block_state` section is H's `block_header_state`: the active
producer schedule (names and single K1 signing keys, in schedule order), the
pending schedule, and the header that re-derives the snapshot's own block id.
The converter (`xpr_import_check --leap-snapshot snapshot.bin`) reads that
section, checks it against itself (number matches the id, the header
re-derives the id exactly, the header's schedule version is the schedule's,
every member holds exactly one weight-one K1 key, H's producer signature
verifies, and the schedule hashes to the signed pending hash), and writes the schedule
into the checkpoint as ordinary contract rows (`eosio`/`eosio`/`migsrcsched`:
a header row plus one row per producer, in order). The checkpoint hash the
ceremony confirms therefore covers the committee.

At restore (and in `xpr_verify_manifest`) the checkpoint's schedule must be
for exactly the terminal block H, carry H's schedule version, attest no
pending schedule, and equal the schedule the manifest records entry for entry
and in order. The recorded copy only transports it; the gate walks H and the
post-H window against the recorded copy, and this binding is what makes that
copy the real one. A checkpoint converted without `--leap-snapshot` carries no
schedule and is refused outright.

What the checkpoint hash can and cannot prove. It exists only after H, so it
can never be published in advance (what can be published at T-30 is the
schedule: its version and hash are readable from any XPR node, and the BPs
compare it before the ceremony). Trust in the checkpoint comes from every
party deriving it themselves, not from anyone handing it over:

- **Signers.** Each BP's voter signs only the checkpoint hash configured from
  that BP's own conversion of its own Leap snapshot at H
  (`xpr_import_check --leap-snapshot`). The voter refuses to adopt the
  coordinator's hash, and refuses to sign if the coordinator's differs from
  the configured one.
- **Validators.** Each validator derives the checkpoint from its own snapshot
  and runs `xpr_verify_manifest --genesis` on it. The verifier requires the
  genesis `migration_checkpoint_sha256` to equal the hash of the checkpoint it
  was given, so a downloaded checkpoint is only as trusted as the validator's
  own derivation agreeing with it. The node enforces this at boot: a
  migration restore requires `migration_local_checkpoint_sha256` (the hash the
  operator derived) and refuses to start unless it equals the genesis pin and
  the manifest hash (see `docs/xpr-cutover-operations.md`, "Self-derived
  checkpoint at boot").

**The successor chain id commits the genesis.** The confirmation's successor
id is `compute_ceremony_chain_id`: the hash of the genesis fields (initial key,
timestamp, configuration, and the migration checkpoint hash), whether or not
the genesis carries an operator-pinned `chain_id` override. The override still
names the chain at runtime, but it commits nothing, so binding the ceremony to
it would let a bundle keep the pinned id and swap the initial key that seeds
the new chain's producer schedule. A coordinator that publishes the override
as the successor id is refused by the voter.

**The conversion must be complete.** `xpr_import_check` refuses to write a
migration checkpoint without the v2 deferred-transaction sidecar (with
`source_chain_id`), because a sidecar-less conversion drops the
replay-protection set and action sequences and lands on a different hash than
the rest of the fleet. `--no-deferred-sidecar` waives it for rehearsal
fixtures only and prints a warning. It also refuses a non-empty arena
directory.

**The conversion is a function of the set of rows.** Arena row ids are
insertion order and the checkpoint lists rows by id, so the hash would depend
on the order each BP's state history emitted rows. The converter therefore
sorts the rows of each table by their own bytes (and the sidecar's deferred
transactions by transaction id) before inserting, and orders permissions
parent-first. A shuffled export, including permissions listed before their
parents, converts to the same bytes (`checkpoint_does_not_depend_on_row_order`).
This removes the assumption that every BP's node emits rows in one order.

**The schedule is anchored in H's own signature.** The id and signature of H
do not directly commit to the active schedule, which would let an attacker
holding a real H snapshot keep H's header and producer entry and swap the
other 20 entries for their own keys. They do commit to something equivalent:
Leap keeps the hash of the last proposed schedule in
`pending_schedule.schedule_hash` after it activates, and every block
signature covers that hash (`sig_digest = sha256(sha256(header_digest ||
blockroot) || pending_schedule_hash)`). With nothing pending, that hash is
`sha256(pack(active_schedule))`. Confirmed on a real four-producer snapshot
(schedule v1): the two hashes are identical. Therefore, for any chain whose
schedule has ever changed (version > 0, which XPR's has):

- the converter refuses a snapshot whose active schedule does not hash to the
  pending hash, and verifies H's signature over that digest against the
  producer's scheduled key;
- the restore gate and `xpr_verify_manifest` require the recorded schedule to
  hash to the schedule hash in the signature-verified H entry.

Substituting any schedule entry now requires H's producer key. Version 0 (a
chain that never changed schedule, i.e. rehearsal fixtures) has only the
genesis schedule, which no hash covers; the block id binds the schedule
version, so a real chain with a changed schedule cannot be presented as
version 0.

What this does not remove: the id of H itself is still a fact from outside
the bundle. Anyone can check it on any XPR node, and each BP's voter compares
it with its own node before signing.

Two further checks close the rest of the attack that earlier versions
allowed (a recorded set the attacker controls, one key signing a fabricated
empty window): every block H..P must be produced by the schedule's own
producer for its timestamp slot (`(slot % (n * 12)) / 12`, with slots
strictly advancing), and the confirmation signs the id of block P so the
quorum attests one specific branch.

## Contract evidence is bound to its account

With the contract vehicle the declaration signatures are the on-chain votes,
so the evidence is only as good as the tie between a vote and the contract it
was cast on. The declaration digest therefore carries the ceremony contract's
**account** (domain `PULSEVM-XPR-HALT-DECLARATION-v2`, the account
length-prefixed after the member set): `init` appends its own account when it
freezes the digest, the voter and the scanner build the same bytes from the
configured contract, and the ceremony tool takes `--contract`. A vote is
therefore a vote for that contract and no other. Evidence scraped from a
look-alike contract on another account, or from one an attacker deployed with
its own `init`, signs a different digest and cannot be presented as the
fleet's; at restore the evidence's contract must equal the account the
declaration binds, and evidence on a declaration that binds none is refused.
Memo-vehicle declarations bind no contract and keep the v1 digest byte for
byte.

What this does not cover is the timing the scanner reports (vote and
finalization heights are exporter-scanned numbers): the votes' signatures are
the real quorum's, and the declaration's pre-commitment timing for a contract
declaration still rests on those scanned heights.

## Post-H window (what the exporter stages)

The version pin does not stop at H. The authoritative schedule comes
from H's own header state (`block-H.state.json`), captured by the
coordinator's own synced node in the same poll iteration that first
observes head == H — the only moment it is guaranteed servable. Header
state is served only while a block is reversible: H goes irreversible as
the chain builds toward P, and no export nodeos can serve it later,
because a node hydrated from the H snapshot takes H as its irreversible
base (verified: `get_block_header_state` for the snapshot head answers
`unknown_block`). So the fetch cannot be deferred to the export, and it
is never a live `get_producer_schedule` query (whose pending schedule
may already have moved on) and never the producers table (whose active
rows are a superset of the schedule). The state is bound to the
snapshotted H id at capture, so a foreign state fails at the freeze, not
at the gate. The rehearsal stages every header from H+1 to the agreed
stop (`block-post-N.json`)
plus each header's `get_block_header_state`
(`block-post-N.state.json`), and the attach tool records all of it: the
schedule at unit weight read from H's header state, each post-H
header hash-linked from the trusted H id with an empty transaction root
and signed by the recorded schedule key for its producer. The state
supplies the two signature inputs the header cannot — the blockroot root
and the pending schedule hash — so the signature is re-verified over
Leap's true digest
(`sha256(sha256(sha256(header) || root) || schedule_hash)`). The state's
hash is bound by the signature itself: only the exact (root, hash) pair
Leap signed recovers to the roster key, so there is no hash-to-roster
comparison to fool — and none is attempted, because with no staged
change Leap serves the EMPTY pending schedule, whose hash cannot equal
the active roster's (proven against live header states on the first
rehearsal run). `P` itself is the ceremony's agreed stop — a fixed H+k
set before the freeze and signed into the step-two confirmation — so the
coverage bound is quorum-attested, not coordinator-typed. The restore
gate re-verifies the packed proof, requires the recorded schedule to
equal the declared set exactly, and requires the staged headers to cover
exactly H+1 through the agreed `P`, so no tail past P can hide traffic
the checkpoint is missing: a header carrying transactions, a rotation,
or a signature from outside the frozen set fails the export, a proof
that stops short of the agreed stop fails the boot, and an unstaged
window fails the boot.

Capture ordering matters: Leap only serves `get_block_header_state` for
still-reversible blocks. The rehearsal therefore captures H's pair in
the same poll iteration that first observes head == H (before
snapshotting), streams each H+1..P tip the moment it appears while the
producer still builds toward the agreed stop, and tops up only the fresh
tip from a validator after the pause. Fetching any pair after finality
has passed fails closed and supersedes the round.

On trust: the fetcher is the coordinator's own infra, not the exporter —
the same trust domain that selects H, computes digests, and runs the
votes — and the fetch is cross-checked five ways. Both frozen-network
validators must report the identical active committee (names and version;
they cannot re-serve H's header state itself — it went irreversible as
they converged — so active-set equality is the strongest cross-node
agreement available); the state id must equal
the snapshotted H id (which equals the checkpoint base); H's own producer
signature must recover to a recorded schedule key; the recorded set must
equal the 15-BP-attested declaration exactly; and every voter's
live-schedule check refuses a roster that is not the real active
schedule. A forged schedule would need the coordinator to fetch a lie,
15 BPs to attest it, and the real producers' signatures to verify
against it — outside any quorum threat model this design admits.

There is deliberately no LIB wait *for signing*. On a large committee
LIB(H) arrives hundreds of blocks after H, so making the confirmation wait
for it would deadlock the halt. The 15-of-21 confirmation quorum over H_ID
stands in for Leap finality, and every scheduled producer stops at the same
agreed P — the voters enforce it locally, independent of confirmation
delivery.

The stop window itself is not free, though: **a Leap snapshot of H is only
finalized once H is irreversible.** Leap writes
`.pending-snapshot-<H id>.bin` and renames it when H goes irreversible. If
every producer stops before that, H stays reversible, the snapshot never
completes, and the exporters have nothing to export (found live with a
four-producer schedule, where LIB(H) arrives tens of blocks after H; on 21
producers expect hundreds). So the agreed P must satisfy
`P - H >= 2 x finality_lag + one producer turn`, where the lag is the
chain's steady-state head-minus-LIB gap. The voter's `--preflight` enforces
this against the live node (`stop window past finality`) and the rehearsal
harness derives its stop lag from the observed gap. The gate accepts up to
4096 post-H blocks, so a longer window costs staging (one block plus one
header state per height, all captured while reversible), not validity.
Choose P at T-14 from a measured lag on the live chain, not from a constant.

Prevention is procedural, verification is cryptographic. On the source
side, the agreed stop PREVENTS post-P traffic: every producer pauses at
P, and the voters re-assert the pause. On our side, the staged proof
VERIFIES the stop held: the gate replays every header H+1 through the
agreed stop rather than trusting the pause. The two halves belong to
different parties — the fleet operates the freeze, the A-Chain checks
it — so a broken freeze cannot strand users: the gate turns it into a
refused boot, loudly, before H+1 is ever produced, instead of promoting
state the schedule never endorsed.

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
