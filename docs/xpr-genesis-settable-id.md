# U-1: genesis-settable successor chain id — assessment

Status: design assessment. No consensus change is made by this note.

## Problem

The successor chain id is `sha256(pack(genesis))` with the packed
genesis committing `migration_checkpoint_sha256`
(`crates/pulsevm_chain_types/src/genesis.rs`, `compute_chain_id`).
The checkpoint only exists after H is exported, so the successor id
only exists after H. Wallets, exchanges, and gateways need the id
weeks earlier (T-14) to ship config. Without a pre-published id they
cannot cut over clients in time.

## Proposal (U-1)

Allow the migration genesis to carry an explicit, operator-pinned
chain id: an optional `chain_id` field. When present, nodes use it
instead of the computed hash; when absent, derivation is unchanged.
The pinned value is published at T-14 through the same governance
decision that fixes H, K, and the ceremony contract — never unilaterally.

## Why it stays safe

Pinning the id removes none of the existing bindings:

- The confirmation still binds `checkpoint_sha256`, the source block
  id, and the platform chain id. A node booting the right id with the
  wrong state fails closed at the restore gate.
- The vote still binds the frozen roster, the schedule version, and H.
- Head agreement across 2/3 of stake still precedes serving traffic.

The id names the chain. The checkpoint, the votes, and the quorum
decide which state under that name is legitimate.

## Sharp edge: two exports, one id

A pinned id makes two competing exports (different checkpoints, same
id) structurally possible. Analysis:

- The losing export cannot recruit quorum: its checkpoint hash does
  not match the published confirmation, so conforming nodes refuse it
  at the gate. The fork dies from lack of 2/3, not from id collision.
- No node may auto-follow a same-id chain with a different checkpoint.
  The gate's checkpoint comparison is equality, not prefix or subset.
- Governance publishes exactly one export (one checkpoint, one
  confirmation set). A second export is a new governance decision,
  not a retry: it needs a new H, because the old H already finalized
  under the first export's history.

## MetalGo cooperation required

Platform-side chain registration assigns random ids today (observed in
rehearsal: `createBlockchainTxs` yields non-deterministic ids). A
pinned successor id requires launcher support to register the fixed id
for the migration chain. This is a MetalGo-side change outside this
repo; the rehearsal harness learns-then-binds as the interim path.
Do not emulate a fixed id by patching the hash locally — every node
must compute or accept the identical value from the identical genesis
bytes.

## Recommendation

1. Add the optional `chain_id` genesis field behind the migration
   extension (absent = current behavior, bit-for-bit).
2. Publish the pinned id at T-14 with H, K, contract, and roster.
3. Keep the confirmation's checkpoint binding unconditional: it is
   what makes a shared id safe.
4. Coordinate the MetalGo launcher change before promising wallets a
   stable pre-H id.
