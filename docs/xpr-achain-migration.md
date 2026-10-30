# XPR Network to A-Chain migration

This is the canonical plan for moving XPR Network state (EOS/Leap) onto the
Metallicus A-Chain running PulseVM as an Avalanche subnet VM. It covers the
cut height, validator coordination, API and gateway cutover, validation gates,
and rollback. It is a migration to a new PulseVM chain, not a continuation of
XPR block IDs or signatures.

The code is authoritative. Where this document and the implementation
disagree, the implementation is a bug or this document is stale — file an
issue either way.

## 1. Background: the machinery already exists

State transfer is implemented and does not need reinventing:

- Export: [`tools/xpr-chainbase-export`](../tools/xpr-chainbase-export/README.md)
  pins XPR Leap 5.0.3, requires a snapshot-only export (no P2P peer, so
  post-snapshot blocks cannot mutate the log before hashing), and emits a
  version-2 migration sidecar with replay-protection state. Promotion requires
  both `validate-mainnet-export.sh` reports; no export is called validated
  without them.
- Import: `pulsevm_database::xpr_import` hydrates Arena from SHiP table deltas
  into `migration.snapshot` plus a manifest bound by `checkpoint_sha256`.
- Genesis binding: `GenesisState::migration_checkpoint_sha256` changes the
  chain ID, so the A-Chain is cryptographically distinct and XPR signatures
  do not replay onto it (see
  [`genesis.rs`](../crates/pulsevm_chain_types/src/genesis.rs)).
- Boot: MetalGo passes `genesis.json` through verbatim; `scripts/run-local.sh`
  already generates migration genesis committed to the checkpoint hash, and
  the five-node harness boots from an imported checkpoint with a fresh
  PulseVM producer schedule.
- Live position: the follow runbook ([`xpr-mainnet-follow.md`](./xpr-mainnet-follow.md))
  tracks the validated replay head that the cut height must be chosen behind.

## 2. What the cut is (and is not)

- XPR keeps producing. The migration is a declared one-way fork: a cutoff
  height H plus a new chain identity. Halting XPR would require two-thirds
  producer coordination on a chain we do not control, with no rollback if the
  A-Chain stalls. The new chain ID plus the declared cutoff gives the same
  safety without XPR-side action beyond announcement.
- Post-H XPR activity is out of scope and is never honored on the A-Chain.
  The bounded history-window tooling (`xpr_apply_history_window`) exists only
  as a fallback; using it as the canonical path would reopen cross-chain
  double-spend and is rejected.
- Contract migration is out of scope here: most contracts need adaptation
  (see `PROTOCOL.md`), tracked per-contract elsewhere.

## 3. Cut height and announcement

1. Pin H as an XPR irreversible (LIB) block at or behind the validated replay
   head. Publish H, its block ID, the exporter source revision, and the
   expected checkpoint SHA-256.
2. Produce the canonical export (snapshot-only, preflight plus both
   validation reports). Require an independent re-export by a second party
   with matching hashes before H is declared final.
3. Attach the id-exact source block to the manifest and generate the
   migration genesis (chain ID committed to the checkpoint hash). Publish
   `genesis.json`, the chain config, and the resulting BlockchainID.
   Rebuild the halt roster at H as the active schedule (names, schedule
   keys, version) with unit weights (`xpr_verify_manifest --emit-roster`
   lists actives as the starting point; trim to the coordinated schedule):
   only members key-anchored to checkpoint state pass the restore
   cross-check, and standbys are simply not in the quorum.
   Validate the finished manifest offline with `xpr_verify_manifest` before
   publishing it — the second exporting party repeats this check on their
   own re-export.
4. Announce on XPR from a recognized account: a memo carrying H, the
   checkpoint hash, the new chain ID and BlockchainID, and the statement
   that activity after H is not honored. Mirror it off-chain to validators,
   exchanges, and frontend operators. The BP commitment backing the
   cutoff is the on-chain cutover ceremony (`contracts/cutover/`, see
   `docs/xpr-halt-ceremony.md`): producers vote the H freeze with their
   block-signing keys, 2/3+1 by count over the frozen schedule (15 of 21),
   manually or via the auto-voter shipped in the upgrade — no XPR
   protocol feature required.

## 4. Validators

1. Stand up the MetalGo subnet and create the A-Chain blockchain with the
   published migration genesis. Validators preload the checkpoint plus
   manifest and verify the hash match at startup: `migration_checkpoint`
   and `migration_manifest` must be configured together, and the genesis
   hash must match the manifest.
2. Key ceremony: the initial PulseVM producer schedule is fresh (it is not
   the XPR schedule). Each A-Chain validator generates or designates its
   block-signing key off-chain; the set of keys and the schedule is
   published alongside the genesis so any party can verify who may produce.
3. Boot threshold: do not open APIs until at least two-thirds of the
   scheduled stake-weighted validator set is online, bootstrapped to H,
   and agreeing on the head block ID. Below that threshold the chain is
   declared not live.
4. XPR producers vote the cutover ceremony (manual tool or the
   auto-voter in the upgrade) but do not switch keys or infrastructure:
   no key reuse. Validator overlap with XPR is allowed but must be
   explicit: overlapping operators run fully separate keys and
   infrastructure for the A-Chain.

## 5. APIs

1. PulseVM JSON-RPC is the primary API. Leap-compatibility routes
   (`nodeos_compat`, including `send_transaction2`) stay enabled so
   existing wallets and `cleos` keep working without changes.
2. Transaction submission goes through `pulsevm.pushTransaction` with
   numeric `compression` (0/1) and the A-Chain chain ID enforced at the
   boundary. Test it with a low-value transfer before announcing
   general availability.
3. Hyperion plus Elasticsearch is reindexed from the A-Chain SHiP stream
   from genesis (which is H state). Until the reindex passes its row-count
   gates, history requests keep serving from the XPR follow stack.
4. The Bloks explorer switches its PulseVM adapter to the A-Chain RPC and
   its history source to the new Hyperion only after gates pass. Producer
   tables and market data keep their existing presentation fallbacks.
5. SHiP consumers re-point from the follow stream to the A-Chain stream;
   stream owners confirm continuity (no gap, no overlap) before the old
   stream is retired.

## 6. Gateways

Current public surface (Caddy plus Cloudflare tunnels) routes per path:
RPC to the replay port, full block payloads to Leap, SHiP to its port,
history to Hyperion, and status endpoints to the status server. The
cutover keeps every hostname and only re-points backends:

1. Stand up the A-Chain stack on parallel backends (new ports) behind the
   same Caddy config shape, verified privately.
2. Flip each route backend (RPC, SHiP, Hyperion, status) only after that
   route's validation gate passes; keep the XPR follow backends running
   until all flips complete.
3. DNS and tunnels do not change; no client reconfiguration is required
   beyond the WebAuth submission endpoint already communicated.
4. Keep the XPR follow stack (feed, replay, Hyperion) running read-only
   for at least one week after the flip as the audit source and instant
   fallback.

## 7. Phases and gates

| Phase | Owner | Gate to next phase |
|---|---|---|
| Pin H, export, independent re-export | Migration operators | Matching checkpoint hashes, both validation reports |
| Publish genesis, announce on XPR | Migration operators | Memo on-chain, off-chain notices acknowledged |
| Validator boot to H, two-thirds online | A-Chain validators | Same head block ID across quorum |
| Private API verification | Migration operators | Low-value transfer round trip, Hyperion row counts |
| Public gateway flip, route by route | Gateway operators | Per-route smoke checks green |
| Retire follow stack | Migration operators | One week stable, audit snapshot archived |

## 8. Validation

- `xpr_import_check` accepts the checkpoint plus manifest; genesis hash
  matches the manifest or startup refuses.
- Two independent A-Chain nodes agree on head block ID from H forward.
- `pulsevm.getInfo` reports the migration chain ID with H as base.
- A low-value transfer submits, relays, and appears in an A-Chain block;
  its receipt root verifies.
- Hyperion row counts reconcile against the export audit before history
  flips.

## 9. Rollback

- Before the gateway flip: fix forward on the A-Chain; XPR is unaffected.
- After a partial flip: re-point the affected route backend to the XPR
  follow stack, which is kept running for this purpose.
- After full flip plus one week stable: rollback is a new migration, not
  a revert; archived artifacts make it reproducible.

## 10. Open questions

1. Who are the A-Chain genesis validators, and who holds the schedule keys?
2. What are the real public hostnames replacing the current staging names?
3. What is the Hyperion full-reindex time budget from H?
4. Which contracts are in the day-one supported set versus later?

## 11. Risk register (grounded 2026-10-15)

Each entry below was verified against the implementation. Residual items
name an owner and block the cited phase gate until closed.

1. Cryptographic replay is dead both ways; procedural replay is not.
   `signing_digest` hashes `chain_id` first
   (`crates/pulsevm_core/src/chain/transaction/signed_transaction.rs`),
   and recovery/verification always runs under the local chain ID — an
   XPR-signed transaction recovers wrong keys on the A-Chain and fails
   authorization, and vice versa. What chain-ID separation cannot do is
   stop an exchange from *crediting* a deposit observed on the wrong
   chain. Mitigation is the exchange runbook in section 12. Owner:
   exchange liaison. Blocks public gateway flip.
2. Quorum-vs-flip ordering needs an abort threshold. Section 4.3 bars APIs
   below two-thirds agreeing on head, but section 6 flips routes one by
   one. Rule: if agreement drops below two-thirds mid-flip, freeze
   remaining flips and re-point completed routes to the follow stack
   (section 9). The two-thirds figure is a declared operational
   threshold; the exact MetalGo subnet stake mechanics live outside this
   repo and must be confirmed against the deployed subnet config before
   validator boot. Owner: chain operators. Blocks validator boot.
3. Key-ceremony publication needs a verifiable channel. Publish the fresh
   schedule as a signed artifact (validator-set multisig over schedule
   plus genesis hash), and pin that artifact's hash in the XPR
   announcement memo — so a spoofed memo or substituted genesis is
   detectable by hash mismatch. No such artifact exists yet. Owner:
   validator set coordinator. Blocks announcement.
4. Split-brain is detectable by construction. New blocks build on the
   anchored source tip plus one
   (`crates/pulsevm_core/src/chain/controller.rs`), so the first A-Chain
   block must be exactly H+1 with the source block ID as parent; SHiP
   streams strictly by block number and waits rather than skipping
   (`crates/pulsevm_core/src/chain/state_history/server/session.rs`).
   Gate: every consumer asserts parent linkage across the H boundary and
   Hyperion row counts match the export audit exactly for all 19 SHiP
   tables before history flips. Post-H XPR drift is irrelevant to the
   A-Chain (new IDs) but must not be served as A-Chain history — the
   Bloks adapter points at exactly one history source at a time. Owner:
   API/indexer operators. Blocks history flip.
5. Startup fails closed on bad artifacts. Checkpoint/manifest/genesis
   mismatch refuses startup (`controller.rs` initialize errors), the
   manifest versions 1 and 2 are accepted and anything else fails closed,
   and single-delta decompression is bounded
   (`crates/pulsevm_database/src/xpr_import.rs`). A malicious alternate
   export therefore cannot boot a node that checks hashes — but nothing
   stops one from booting nodes that skip checks, so validators must
   verify hashes out-of-band against the memo. Snapshot-DoS is bounded
   by the same guards. Owner: security reviewer. Blocks validator boot.

## 12. Exchange coordination runbook

Named contact plus written acknowledgement per venue; silence is not
consent and blocks the announcement phase.

- T-14 days: send every venue the MetalGo blockchain (platform) ID —
  known as soon as the A-Chain is created, which must happen before the
  freeze — plus the ticker plan, the freeze/re-enable procedure below,
  and a staging endpoint. The ceremony binds this id (not the
  checkpoint-derived successor id, which only exists after the H export);
  venues must reject anything signed under any other id. Require a named
  contact and a test deposit on staging.
- T-7 days: confirm each venue's freeze implementation and replay the
  negative test: submit a known pre-H XPR transaction hash to the
  A-Chain and confirm rejection (wrong chain ID); submit an A-Chain
  transaction to XPR tooling and confirm rejection.
- H: venues halt deposits and withdrawals at H plus 180 confirmations
  (~90 seconds at 0.5-second blocks; adjust if block time changes) and
  snapshot balances at the H LIB for reconciliation.
- Re-enable: deposits only carrying the A-Chain chain ID, under the
  agreed ticker. Post-H XPR deposits are never credited — the XPR chain
  keeps producing, so this rule must be explicit, not assumed.
- Memo/tag handling does not change: deposit memo schemes carry over
  unchanged since account names and memo conventions are part of the
  migrated state.

## 13. Go/no-go checklist

Every item is measurable; any red item aborts the phase.

- Export: two independent exports, matching checkpoint hashes, both
  validation reports green.
- Announcement: memo on-chain, signed schedule artifact published with
  its hash pinned in the memo, all venue contacts acknowledged.
- Validator boot: quorum online with identical head block ID for 30
  consecutive blocks; subnet stake mechanics confirmed against the
  deployed config.
- Private verification: low-value transfer submits, relays, lands in an
  A-Chain block, receipt root verifies; negative replay tests pass both
  directions.
- History: Hyperion row counts match the export audit exactly for all
  19 SHiP tables; parent linkage H to H+1 asserted by every consumer.
- Gateway flip: per-route smoke checks green; abort threshold armed
  (section 11.2); follow stack confirmed running as fallback.
- Steady state: one full week green before the follow stack may be
  retired, with the audit snapshot archived.
6. Deferred queue crosses the boundary by design. Unexpired deferred
   transactions in the sidecar execute on the A-Chain with A-Chain state.
   Audit the deferred list at H: anything whose XPR-side assumptions
   (oracle values, time-sensitive logic) no longer hold must be cancelled
   pre-export or handled by the contract owners on day one. The export
   enforces the mechanical half pre-H: the attach tool and the offline
   verifier refuse any sidecar with a deferred due in the (H, P] pause
   window (`check_no_deferred_due_in_window` in
   `crates/pulsevm_database/src/xpr_import.rs`), because a row executable
   on a post-H block would set the block's `transaction_mroot` and fail
   the boot closed at the emptiness gate. The rejection names the sender
   and transaction so the row can be cancelled pre-export. Regular
   transactions are expiry-checked with no delays or extensions
   (`crates/pulsevm_core/src/chain/transaction/transaction.rs`), so no
   stale pre-H transaction can execute late. Owner: contract owners plus
   migration lead. Blocks export promotion.

## 14. Halt commitment versions (implemented)

- Version 1: single producer key over the terminal block (`PULSEVM-XPR-HALT-v1`).
  Legacy manifests without a roster keep this path.
- Version 2: the signed digest additionally binds `checkpoint_sha256`
  (`PULSEVM-XPR-HALT-v2`), so a commitment cannot be replayed onto another
  export of the same block. Attach with
  `cargo run -p pulsevm_core --example xpr_attach_source_block -- <manifest>
  <get-block> <out> --halt-key-v2 <wif>`.
- Weighted roster: retired. The roster is the declared set at unit weight
  (`HaltWeight::MEMBER` for every member — anything else fails closed as an
  exporter moving the denominator), and the restore verifies a strict count
  quorum (`signed*3 > total*2`, so exactly-two-thirds fails) instead of the
  single-key path, for version 1 and 2 commitments alike. Verification lives
  in `crates/pulsevm_chain_types/src/migration.rs`, the restore gate in
  `crates/pulsevm_core/src/chain/controller.rs`.
- State binding: post-restore, every rostered name must resolve to the same
  signing key in the checkpoint's `eosio.system` `producers` table, so the
  exporter cannot invent members.
- Schedule pin at export: `xpr_attach_source_block --schedule
  <get_producer_schedule.json>` records the frozen active schedule (names,
  schedule keys, version) into `MigrationManifest.halt_schedule`, pinned to
  H's header version. The restore gate requires the recorded schedule to
  equal the declared set exactly, both ways, so the post-H signatures and
  the declaration quorum resolve against the same set.
- Post-H emptiness proof: `xpr_attach_source_block --post-block
  <get_block.json>` (repeatable, in height order) records every header from
  H+1 to the pause head into `MigrationManifest.halt_post_blocks`. Each
  header is authenticated at record time — hash-linked from the trusted H
  id, empty transaction root, no schedule change or version rotation, signed
  by the recorded schedule key for its producer — and the restore gate
  re-verifies the packed proof from the manifest. An absent proof fails
  closed: unattested windows do not boot.
