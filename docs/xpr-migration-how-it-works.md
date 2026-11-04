# XPR → A-Chain migration: how it works, why it holds, and what we need from you

XPR Network state is moving to a new home: the Metallicus A-Chain, running
PulseVM as an Avalanche subnet VM. Same accounts, same keys, same balances —
new chain, new rules, no trust-me steps. This document explains the mechanism
in plain language, shows the proof that it already works end to end, and ends
with a call to action: the concrete inputs we need from block producers,
gateway operators, wallet and exchange teams, and auditors to set the date.

The operational plan (cut height, phases, gates, rollback) lives in
[`xpr-achain-migration.md`](https://github.com/MetalBlockchain/pulsevm/blob/main/docs/xpr-achain-migration.md). That document is the
checklist; this one is the case for why the checklist will succeed. Where the
two disagree, the code is authoritative and the mismatch is a bug — open an
issue against the repo.

## The decision we need from you

1. Approve this approach: declared cutoff, hash-verified export, new
   chain identity, quorum-gated restore — as written here.
2. Name two people: a validator coordinator (owns keys, schedule
   artifact, boot) and an exchange liaison (owns venue outreach and
   the freeze procedure).
3. Set the H-selection meeting date. Every timeline date runs backwards
   from the day its inputs are checked off; that meeting fills in the
   owner and due date for each box in the call to action.

## The idea in one paragraph

We pick a cutoff block H on XPR and prove, cryptographically, that everyone
agrees on the exact state at H. We export that state, bind it to a new chain
identity, and boot a fresh validator network directly from it — no
genesis balances to invent, no replay of history required to boot. The first
A-Chain block is H+1, parent-linked to the XPR halt block, so there is exactly
one unbroken chain of custody from the old network to the new one. Every step
is verified by hash comparison, not by trusting an operator. XPR itself keeps
running independently; this plan proposes no shutdown of the old chain.

## How it works — follow one user through it

Alice holds 1,000 XPR, has a recurring payment scheduled to go out next
week, and keeps 200 XPR on an exchange. Here is what happens to each of
those, step by step. No step asks anyone to trust an operator: every one
ends in a hash comparison anyone can repeat.

**1. The freeze everyone can check.** At an agreed block H — say a Tuesday
noon block the whole ecosystem knows in advance — XPR's own block producers
sign a joint statement: the exact state at block H is X. Not one producer:
a weighted two-thirds of them. And the signature covers the fingerprint of
the exported state itself, so it cannot be cut and pasted onto a different
export. Anyone can verify those signatures against the producers XPR
already trusts. Nothing stops on XPR; the statement just draws a line.
Everything up to H moves over. Everything after H stays behind.

*Alice does nothing. Her 1,000 XPR, her scheduled payment, and the
exchange's 200 sit exactly where they are.*

**2. The state is copied twice, by two independent parties.** An exporter
takes a full snapshot of XPR at H: accounts, balances, permissions,
scheduled payments, contract tables — with the network peer disconnected,
so no new block can sneak in mid-copy. Then a second party repeats the
whole thing from scratch. The two copies must match byte-for-byte before
H is declared final. No match, no migration.

*Alice's 1,000 XPR appears in both copies. Her scheduled payment appears
in both copies' pending list, trigger conditions intact. The exchange's
200 appears too.*

**3. The new chain gets its own identity.** The copied state is sealed into
the first block of a brand-new chain, and the sealing changes the chain's
fingerprint. This is the anti-scam feature: a transaction signed for XPR
is gibberish on the new chain and vice versa, mathematically — nobody can
replay Alice's old payments to double-spend them. The remaining replay
risk is purely procedural (an exchange crediting a deposit seen on the
wrong chain), which is why the exchange runbook exists.

**4. Validators boot from the copy — and prove it.** The new chain's
validators each load the snapshot and check its fingerprint before
starting; any mismatch and that node refuses to boot. They also verify
the two-thirds halt quorum and confirm every signer in it against the
producers table inside the snapshot itself, so nobody can invent
signers. A malicious alternate export cannot boot a single honest node.

*An example of the checks firing: if the checkpoint hash differs by one
byte from what the halt commitment signed, startup aborts with a hash
mismatch instead of a running chain. That failure is the security model
working, and it is tested, not assumed.*

**5. The chain picks up exactly where XPR left off — then proves it.**
The first new block is H+1 and names the XPR halt block as its parent:
one unbroken chain of custody. Then three audits run automatically.
First, every account balance is re-checked against the snapshot (4 out
of 4 in rehearsals). Second, test transactions sent just before the halt
are audited exactly once across the swap (10 out of 10 — nothing lost,
nothing duplicated). Third, a low-value live transfer lands in a new
block and its receipt verifies. Any gate red, the process stops before
anything public moves.

*Alice on day one: same account name, same key, 1,000 XPR. Her scheduled
payment carries over with its trigger intact. Her wallet needed exactly one update
— the new chain ID — shipped by her wallet provider before the day. The
exchange paused deposits and withdrawals around H, reconciled its 200
against its own snapshot, and re-enabled under the agreed ticker. Anyone
emailing her about "claiming" migrated tokens or "swapping" keys is
running the scam the announcement memo warned about in advance.*

## Proof it already works

This is not a design doc for future code. The full ceremony has been run
end to end, twice, on fresh chains, with all checks passing:

- **Local rehearsal (fresh chain, v2 ceremony): halt at H=328.**
  Five-node restore with tip 328 == H and head ID equal to the committed
  halt block. H+1=329 parent-linked. State equivalence 4/4 accounts.
  Boundary traffic 10/10 exactly-once. Verdict: `PASS`.
- **EC2 rehearsal (fresh chain, v2 ceremony): halt at H=326.**
  Same gates, same verdict: `PASS` — block 327 builds on the halt block,
  4/4 equivalence, 10/10 boundary. Run on a 32-core node alongside live
  mainnet catchup work, on stock amd64 paths.
- **Unit level:** 13 + 35 + 8 migration tests green, plus receipt-shape
  parity against a live XPR testnet transaction (digest reproduces Leap's
  txid byte-for-byte), exactly-once boundary audits, and negative tests
  (wrong chain ID rejected both directions).
- **Harness:** the rehearsal itself is scripted (`docker/handover/`),
  deterministic, and re-runnable — every number above regenerates on
  demand. Evidence (checkpoints, manifests, logs) is archived per run.

What is *not* yet proven, honestly: a live ceremony with distinct
per-validator halt keys (rehearsals use a single-member fixture roster),
and the production gateway flip (rehearsed privately per route, not the
public cutover). Both are scoped, not open-ended.

## What could go wrong, and what stops it

No migration doc is credible without this. Each risk names its backstop:

- **Bad export.** Two independent exports must match byte-for-byte, plus
  both validation reports. A mismatch stops the process before H is
  ever declared — there is nothing to roll back from.
- **A-Chain stalls after boot.** Validators refuse to start on any
  artifact mismatch, and the network is not declared live below
  two-thirds agreement on head. The fix-forward happens on a chain
  nobody uses yet; XPR is unaffected.
- **Gateway flip goes wrong.** Routes flip one at a time, each with a
  smoke check and an abort that re-points that route at the XPR follow
  stack — which keeps running read-only for a week as the audit source
  and instant fallback. A bad flip is a re-point, not an incident.
- **Exchange credits the wrong chain.** New chain ID makes protocol
  replay impossible; the remaining risk is a venue crediting an XPR-side
  deposit after H. Mitigation is the freeze procedure plus the negative
  replay tests every venue runs on staging first.
- **Cost of the transition.** Parallel backends, reindex compute, and a
  week of dual-running the follow stack. That spend is the price of the
  fallback above; it ends when the follow stack archives.

## What changes for clients

Deliberately little, and every change is announced with a test path:

- **Accounts, keys, balances, memos:** unchanged. Your keys work, your
  balances carry over, deposit memo schemes are identical — they are part
  of the migrated state.
- **Chain ID:** new. Wallets and tooling must point at the A-Chain ID;
  the old XPR signatures do not validate here (by design).
- **Endpoints:** same hostnames, re-pointed backends — plus a staging
  endpoint published ahead of time for integration testing.
- **APIs:** PulseVM JSON-RPC is primary; Leap-compatible routes
  (`v1/chain/*`, including `send_transaction`) stay enabled so existing
  wallets and `cleos` keep working without changes.
- **History:** Hyperion is reindexed from the A-Chain from H-state.
  Until row-count gates pass, history keeps serving from the XPR stack.
  Explorers flip history source only after the gates.
- **What does not happen:** no airdrop claim, no token swap, no new
  keys to generate. Anything asking for those during the migration is
  a scam — the announcement memo will say so explicitly.

## Call to action: what we need from each team

Concrete artifacts only — no status updates, no acknowledgements. The
date gets set once every box has something checkable in it.

**XPR block producers:**
- [ ] Cutoff memo posted from a recognized account: H, checkpoint
  hash, new chain ID and BlockchainID, schedule-artifact hash.
- [ ] One coordination contact and channel for cutoff week.

**A-Chain genesis validators:**
- [ ] Block-signing public keys submitted to the coordinator,
  plus the validator-set multisig over schedule + genesis hash.
- [ ] Nodes on staging, peered and monitored, producing test blocks.
- [ ] Subnet stake config confirmed against the two-thirds boot rule.

**Gateway and endpoint operators:**
- [ ] Final public hostnames for every staging name in the plan.
- [ ] TLS certs, tunnel IDs, and A-Chain backend ports per route
  (RPC, SHiP, Hyperion, status).
- [ ] Per-route smoke check: exact request, expected response, abort
  action that re-points the route at the follow stack.
- [ ] WebAuth submission endpoint URL.

**Wallet, explorer, and indexer teams:**
- [ ] Chain ID + BlockchainID behind a feature flag, tested against
  staging, with the flip procedure documented.
- [ ] Hyperion reindex measured on a staging snapshot: hours from H,
  plus the row-count gate query used to verify it.
- [ ] Explorer cutover order: RPC adapter first, history source
  second, each with its rollback step.
- [ ] SHiP continuity check: overlapping block numbers between old
  and new stream before the old one retires.

**Exchanges and custodians:**
- [ ] Named technical contact and staging endpoint credentials.
- [ ] Ticker decision (same or new) applied on staging.
- [ ] Test deposit landed and visible on staging.
- [ ] Freeze height logic (H + 180 confirmations) implemented and
  the negative replay tests passing both directions.
- [ ] Balance snapshot query at H LIB, reconciled against staging.

**Contract owners:**
- [ ] Day-one contract list, named explicitly.
- [ ] Deferred transactions at H that depend on XPR-side state
  (oracles, timers): cancel pre-export or ship the day-one handler.

**Auditors and security reviewers:**
- [ ] Second independent re-export with matching hashes.
- [ ] Hash-check script validators run before booting from the
  published artifacts.
- [ ] Negative replay tests and schedule artifact verified.

**Migration operators (us):**
- [ ] Publish H, block ID, exporter revision, checkpoint SHA-256,
  genesis, chain config, BlockchainID.
- [ ] Post the XPR memo with the schedule-artifact hash pinned in it.
- [ ] Follow stack stays read-only for one week post-flip, then
  archived.

## Timeline

T-14 days: venues get chain ID, ticker plan, freeze procedure, staging
endpoint. T-7: freeze implementations confirmed, negative tests replayed.
H: halt commitment, export, boot, H+1. H+1 week stable: retire the follow
stack, archive the audit snapshot. Every date is set backwards from the
inputs above — the day the last box is checked is the day we announce H.
