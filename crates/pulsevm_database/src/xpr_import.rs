//! Input boundary for importing an XPR chainbase snapshot into Arena.
//!
//! XPR's Leap `state_history_plugin` writes the first accepted block in an
//! empty chain-state-history log as a complete set of SHiP `table_delta`s. This
//! module checks that physical log record and exposes the uncompressed table
//! frames. Hydration deliberately lives above this layer: it must make
//! table-specific compatibility decisions rather than treating arbitrary source
//! bytes as an Arena checkpoint.

use std::{
    collections::{
        BTreeMap,
        HashMap,
        HashSet,
    },
    fmt,
    fs::{
        self,
        File,
    },
    io::{
        ErrorKind,
        Read,
        Seek,
        SeekFrom,
    },
    path::Path,
};

use flate2::read::ZlibDecoder;
use pulsevm_crypto::Digest;
use serde::{
    Deserialize,
    Serialize,
};
use sha2::{
    Digest as Sha2Digest,
    Sha256,
};

use crate::{
    ChainConfigV0,
    Database,
    Float128,
    U256,
};

/// XPR Leap writes `magic(8) + block_id(32) + payload_size(8)` before every
/// state-history payload, followed by an eight-byte copy of the record's file
/// offset. These sizes are fixed by `state_history_log_header` in XPR Leap.
const LOG_HEADER_LEN: usize = 8 + 32 + 8;
const LOG_TRAILER_LEN: usize = 8;
const PAYLOAD_FORMAT_LEN: usize = 4;
const DECOMPRESSED_SIZE_LEN: usize = 8;

/// Upper bound for a single imported full-state delta. This is an import-time
/// guard, not a network limit; the streaming hydrator will avoid retaining this
/// whole buffer once table decoding is wired in.
const MAX_DECOMPRESSED_DELTA_LEN: u64 = 64 * 1024 * 1024 * 1024;

/// A decoded SHiP `table_delta` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDelta {
    /// SHiP table name, for example `account` or `contract_row`.
    pub name: String,
    pub rows: Vec<TableDeltaRow>,
}

/// One row in a table delta. A full-state export must have only `present`
/// rows; later validation rejects a removal before any Arena mutations occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDeltaRow {
    pub present: bool,
    /// Type-specific `fc::raw` payload from XPR state history.
    pub data: Vec<u8>,
}

/// The first physical entry in an XPR `chain_state_history.log`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateHistoryEntry {
    pub magic: u64,
    pub block_id: [u8; 32],
    pub deltas: Vec<TableDelta>,
}

/// Bounded framing and table-shape summary for an XPR history log. The initial
/// full-state payload is skipped after framing is checked, avoiding a
/// multi-gigabyte decompressed allocation in the checker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateHistoryWindowSummary {
    pub first_block_id: [u8; 32],
    pub first_payload_bytes: u64,
    pub entries: u64,
    pub post_snapshot_entries: u64,
    pub last_block_id: [u8; 32],
    pub table_rows: BTreeMap<String, u64>,
    pub generated_transactions: u64,
    pub complete: bool,
}

/// Counts of the portable rows committed by [`hydrate_full_state`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSummary {
    pub global_properties: u64,
    pub accounts: u64,
    pub account_metadata: u64,
    pub code_rows: u64,
    pub permissions: u64,
    pub permission_links: u64,
    pub resource_limits: u64,
    pub resource_usage: u64,
    pub resource_states: u64,
    pub resource_configs: u64,
    /// Activated Leap protocol features observed in the source snapshot. They
    /// are retained in Arena's protocol-state row for lossless SHiP export;
    /// the destination is still a new Pulse chain and does not replay the
    /// source activation schedule.
    #[serde(default)]
    pub source_activated_protocol_features: u64,
    /// Added after manifest version 1 was already emitted by local migration
    /// fixtures. Absent means the older artifact contained no deferred rows.
    #[serde(default)]
    pub deferred_transactions: u64,
    /// Unexpired input-transaction IDs retained across cutover so a signed
    /// source transaction cannot execute a second time on the target chain.
    #[serde(default)]
    pub input_transactions: u64,
    pub contract_tables: u64,
    pub contract_rows: u64,
    pub index64_rows: u64,
    pub index128_rows: u64,
    pub index256_rows: u64,
    pub index_double_rows: u64,
    pub index_long_double_rows: u64,
}

/// One weighted-roster entry for halt-quorum verification, in the
/// human-inspectable string-key form the manifest stores. Keys parse to
/// [`pulsevm_chain_types::HaltRosterEntry`] via [`MigrationManifest::roster_entries`].
/// Weights are decimal strings in JSON (see [`pulsevm_chain_types::HaltWeight`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationHaltRosterEntry {
    pub producer: String,
    pub key: String,
    pub weight: pulsevm_chain_types::HaltWeight,
}

/// One memo-vehicle declaration account: the on-chain name committing to
/// the declaration digest, plus the Antelope slot it was created in. The
/// names are deterministic from the digest (`h` + round letter + hex
/// nibbles mapped to `a`–`p`), so the gate re-decodes them instead of
/// trusting the exporter; the slot must predate H. Both are bound by the
/// checkpoint only through existence: the restore gate and the offline
/// verifier require every recorded name to exist in the restored state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationMemoAccount {
    pub name: String,
    pub created_slot: u32,
}

/// A durable, human-inspectable commitment to one XPR-to-Arena conversion.
///
/// The arena checkpoint envelope protects its payload, while this manifest
/// protects the complete envelope and ties it to the exact state-history input
/// from which it was created. Nodes require it at migration startup so a path
/// alone can never silently select a different checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationManifest {
    pub version: u16,
    pub source_state_history_sha256: String,
    pub source_block_id: String,
    /// Canonically packed source block at the checkpoint boundary. This is
    /// optional for legacy manifests, but a node needs it when bootstrapping a
    /// checkpoint above genesis so the local accepted-block journal has an
    /// id-exact anchor instead of inventing a synthetic block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_block: Option<String>,
    /// Source chain identity recorded by the sidecar. The target Pulse chain
    /// intentionally receives a new chain id, so this is provenance only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_chain_id: Option<String>,
    pub checkpoint_sha256: String,
    pub checkpoint_revision: i64,
    /// The old network's signed halt commitment. Optional for legacy
    /// manifests; when present the restore verifies it against the source
    /// block before trusting the checkpoint, so a node never promotes state
    /// the source chain did not agree to freeze.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_commitment: Option<pulsevm_chain_types::HaltCommitment>,
    /// Step one of the two-step cutover: the source schedule's signed
    /// declaration that `last_height` is the last block it authors on the
    /// source chain id. Made while H is still in the future and recorded
    /// on the source chain before H arrives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_declaration: Option<pulsevm_chain_types::HaltDeclaration>,
    /// Step two of the cutover: the same quorum's confirmation binding the
    /// declaration to the terminal block id, the checkpoint, and the
    /// successor chain id. Required whenever `halt_declaration` is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_confirmation: Option<pulsevm_chain_types::HaltConfirmation>,
    /// Block height carrying the declaration commitment (memo block or the
    /// block by which the declaration quorum was complete on-chain).
    /// Provenance for the vote-timing rule; absent when signatures were
    /// collected off-chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_declaration_inclusion: Option<u32>,
    /// Block height carrying the confirmation quorum on-chain. Must postdate
    /// H: a confirmation references H_ID, which cannot exist inside H
    /// itself. Absent when the confirmation was signed off-chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_confirmation_inclusion: Option<u32>,
    /// Ceremony freshness bound K: a declaration inclusion older than H-K
    /// is stale and fails closed. Unset means no freshness bound is
    /// claimed; the structural bound (inclusion strictly before H) always
    /// applies when an inclusion is recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_max_declaration_lag: Option<u32>,
    /// Ceremony liveness bound J: a confirmation inclusion past H+J misses
    /// the deadline and fails closed. Unset means no deadline is claimed;
    /// the structural bound (inclusion strictly after H) always applies
    /// when an inclusion is recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_max_confirmation_lag: Option<u32>,
    /// Commits the chainbase sidecar that supplies every field SHiP v0 omits,
    /// including replay-protection rows. The field keeps its original name for
    /// migration-manifest compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferred_transaction_sidecar_sha256: Option<String>,
    /// Weighted producer roster for halt-quorum verification. Absent for
    /// version 1 manifests, whose restore falls back to the single-key path.
    /// Present implies version 2 (see [`MigrationManifest::with_halt_roster`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_roster: Option<Vec<MigrationHaltRosterEntry>>,
    /// On-chain cutover-contract evidence for the step-one declaration: the
    /// captured `ceremony` singleton plus every `vote` action the exporter
    /// scanned. When present, the verifier replays the tally off-chain
    /// (digest link, windows, membership, recomputed weights, strict
    /// quorum) instead of trusting the recorded inclusion block alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_contract_ceremony: Option<pulsevm_chain_types::HaltContractCeremony>,
    /// The producer-schedule version every vote — and the terminal block —
    /// sat under, attested by the exporter. A rotation mid-ceremony changes
    /// the schedule version, so unanimity here proves the frozen set was
    /// the active schedule for the whole window; combined with the key-anchored
    /// schedule check against checkpoint state, a divergent schedule fails
    /// closed either as a stale version or a mismatched set. Required for the
    /// two-step pair (memo and contract vehicles alike): the pair verifier
    /// pins it to H's header version unconditionally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_schedule_version: Option<u32>,
    /// The active producer schedule as read from H's header state
    /// (names plus schedule keys, unit weights). The pair verifier requires
    /// it to equal the declared set exactly: the declaration must name the
    /// recorded schedule, no more and no less. Recorded by
    /// `xpr_attach_source_block --halt-state` from the header state captured
    /// at the freeze instant (header state is served only while reversible,
    /// and no export nodeos can serve H later) — never from a live
    /// `get_producer_schedule` query, which an exporter could point
    /// anywhere; publication of the schedule hash weeks ahead (T-30) is
    /// what lets every party check the recorded set is the coordinated one
    /// rather than an exporter invention — the gate binds it to the
    /// declaration, the checkpoint (via the confirmed sha), and H's
    /// version, but the coordinated set itself is a governance fact, not a
    /// derivable one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_schedule: Option<Vec<MigrationHaltRosterEntry>>,
    /// Packed signed XPR blocks H+1 through the pause head, in order: the
    /// emptiness proof for the post-H window. The pair verifier hash-links
    /// every header from the trusted H id, requires empty transaction
    /// roots and producer signatures from the recorded schedule, derives
    /// every block id from its header, and rejects schedule changes in the
    /// window — so a non-participating producer's transactions cannot hide
    /// behind fleet procedure. The window is never empty (the pause head
    /// sits strictly past H): an empty list fails closed, and absence is
    /// not an unattested window. Recorded by
    /// `xpr_attach_source_block --post-block` after the pause, with each
    /// header's signature inputs from `--post-state`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_post_blocks: Option<Vec<String>>,
    /// Packed signed XPR cutover block H itself (root || schedule-hash ||
    /// header || signature || block-id — no counts, because H may carry
    /// traffic): the H signature proof. The gate parses it with the shared
    /// entry reader, checks the derived id is H with H's schedule version,
    /// and requires the producer signature — over Leap's true digest with
    /// the entry's recorded root and schedule hash — to recover to the
    /// recorded schedule key for H's producer. The recorded window is bound
    /// by this signature, so the proof cannot open on an unattested H.
    /// Recorded by `xpr_attach_source_block --halt-state` from H's
    /// `get_block` plus H's `get_block_header_state`; absence fails closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_h_block: Option<String>,
    /// Export-time attestation of whether the checkpoint carries a proposed
    /// producer schedule in `global_property`. Must be `Some(false)`: a
    /// checkpoint taken mid-rotation would boot the new chain with a pending
    /// proposal the ceremony never froze, so the restore fails closed on
    /// `Some(true)` (proposed) and on `None` (unattested). Derived by
    /// `record_halt_schedule` from the same header state the roster comes
    /// from — never hand-typed — so a staged pending schedule fails the
    /// record fast; the raw bytes are not recoverable from the checkpoint
    /// afterward (hydrate keeps only the parsed chain config), so absence
    /// cannot be re-derived at restore time.
    /// Memo-vehicle declaration accounts: the on-chain names committing to
    /// the declaration digest, with the Antelope slot each was created in.
    /// Recorded by `xpr_attach_source_block --memo-accounts` from the
    /// harness-captured `get_account` responses (names re-decoded to the
    /// digest and creation required before H at record time). The pair
    /// verifier re-decodes the names and re-checks the timing; the restore
    /// gate and the offline verifier additionally require every recorded
    /// name to exist in the restored checkpoint state — that existence is
    /// what proves the declaration landed on-chain before H, instead of a
    /// bare asserted inclusion height. Absent for the contract vehicle
    /// (whose scanned votes carry their own block heights) and for legacy
    /// commitments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_proposed_schedule: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_memo_accounts: Option<Vec<MigrationMemoAccount>>,
    pub import_summary: ImportSummary,
}

impl MigrationManifest {
    pub const VERSION: u16 = 1;
    pub const VERSION_V2: u16 = 2;

    pub fn new(
        source_state_history: &[u8],
        source_block_id: [u8; 32],
        checkpoint: &[u8],
        checkpoint_revision: i64,
        import_summary: ImportSummary,
    ) -> Self {
        Self {
            version: Self::VERSION,
            source_state_history_sha256: hex::encode(Digest::hash(source_state_history).as_bytes()),
            source_block_id: hex::encode(source_block_id),
            source_block: None,
            source_chain_id: None,
            checkpoint_sha256: hex::encode(Digest::hash(checkpoint).as_bytes()),
            checkpoint_revision,
            deferred_transaction_sidecar_sha256: None,
            halt_commitment: None,
            halt_declaration: None,
            halt_confirmation: None,
            halt_declaration_inclusion: None,
            halt_confirmation_inclusion: None,
            halt_max_declaration_lag: None,
            halt_max_confirmation_lag: None,
            halt_roster: None,
            halt_contract_ceremony: None,
            halt_schedule_version: None,
            halt_proposed_schedule: None,
            halt_memo_accounts: None,
            halt_schedule: None,
            halt_post_blocks: None,
            halt_h_block: None,
            import_summary,
        }
    }

    /// Bind this migration manifest to the exact chainbase sidecar verified
    /// during import. It is separate because SHiP omits transaction dedupe,
    /// action-sequence, and generated-transaction scheduling state.
    pub fn with_deferred_transaction_sidecar(mut self, sidecar: &[u8]) -> Self {
        self.deferred_transaction_sidecar_sha256 =
            Some(hex::encode(Digest::hash(sidecar).as_bytes()));
        self
    }

    /// Record the source chain identity independently of the target chain id.
    pub fn with_source_chain_id(mut self, source_chain_id: [u8; 32]) -> Self {
        self.source_chain_id = Some(hex::encode(source_chain_id));
        self
    }

    /// Attach the weighted producer roster for halt-quorum verification and
    /// mark the manifest version 2. Version 1 manifests (no roster) keep the
    /// single-key restore path.
    pub fn with_halt_roster(mut self, roster: Vec<MigrationHaltRosterEntry>) -> Self {
        self.version = Self::VERSION_V2;
        self.halt_roster = Some(roster);
        self
    }

    /// Parse the manifest roster into verifier entries. Returns `Ok(None)`
    /// when the manifest carries no roster. Verification entry points must
    /// treat `None` as a rejection: a roster-less commitment cannot prove a
    /// schedule quorum, so the single-key path is not accepted anywhere.
    /// Every transported weight must be exactly 1 (the frozen schedule, not
    /// a vote-weight tally): an exporter cannot move the denominator.
    pub fn roster_entries(
        &self,
    ) -> Result<Option<Vec<pulsevm_chain_types::HaltRosterEntry>>, String> {
        let Some(roster) = self.halt_roster.as_ref() else {
            return Ok(None);
        };
        roster
            .iter()
            .map(|entry| {
                if entry.weight != pulsevm_chain_types::HaltWeight::MEMBER {
                    return Err(format!(
                        "halt roster weight for {} is {} (expected the schedule weight 1)",
                        entry.producer, entry.weight.0
                    ));
                }
                let key =
                    pulsevm_crypto::k1::K1PublicKey::from_string(&entry.key).map_err(|e| {
                        format!("halt roster key for {} invalid: {e:?}", entry.producer)
                    })?;
                Ok(pulsevm_chain_types::HaltRosterEntry {
                    producer: entry.producer.clone(),
                    key,
                    weight: entry.weight,
                })
            })
            .collect::<Result<Vec<_>, String>>()
            .map(Some)
    }

    /// Supported manifest versions: 1 (single-key halt) and 2 (roster +
    /// checkpoint-bound halt). Anything else fails closed.
    fn check_version(&self) -> Result<(), String> {
        if self.version != Self::VERSION && self.version != Self::VERSION_V2 {
            return Err(format!(
                "unsupported migration manifest version {} (expected {} or {})",
                self.version,
                Self::VERSION,
                Self::VERSION_V2
            ));
        }
        Ok(())
    }
    /// Verify that `checkpoint` is precisely the artifact this manifest
    /// describes. The checkpoint envelope itself is checked by restore; this
    /// method establishes its migration provenance before restore begins.
    pub fn verify_checkpoint(&self, checkpoint: &[u8]) -> Result<(), String> {
        self.check_version()?;
        let actual = hex::encode(Digest::hash(checkpoint).as_bytes());
        if actual != self.checkpoint_sha256 {
            return Err(format!(
                "checkpoint SHA-256 {actual} does not match manifest {}",
                self.checkpoint_sha256
            ));
        }
        let header = crate::snapshot::peek_header(checkpoint)
            .map_err(|error| format!("invalid checkpoint envelope: {error}"))?;
        if header.revision != self.checkpoint_revision {
            return Err(format!(
                "checkpoint revision {} does not match manifest {}",
                header.revision, self.checkpoint_revision
            ));
        }
        Ok(())
    }

    /// Verify a checkpoint directly from disk without materializing a
    /// multi-gigabyte envelope in the controller process.
    pub fn verify_checkpoint_path(&self, checkpoint: impl AsRef<Path>) -> Result<(), String> {
        let path = checkpoint.as_ref();
        self.check_version()?;
        let mut file = File::open(path)
            .map_err(|error| format!("cannot read checkpoint {}: {error}", path.display()))?;
        let length = file
            .metadata()
            .map_err(|error| format!("cannot stat checkpoint {}: {error}", path.display()))?
            .len();
        if length < crate::snapshot::HEADER_LEN as u64 {
            return Err("checkpoint is shorter than its snapshot envelope header".into());
        }
        let mut header_bytes = vec![0u8; crate::snapshot::HEADER_LEN];
        file.read_exact(&mut header_bytes)
            .map_err(|error| format!("cannot read checkpoint header: {error}"))?;
        let header = crate::snapshot::peek_header(&header_bytes)
            .map_err(|error| format!("invalid checkpoint envelope: {error}"))?;
        let expected_length = (crate::snapshot::HEADER_LEN as u64)
            .checked_add(header.payload_len)
            .ok_or_else(|| "checkpoint length overflows u64".to_string())?;
        if length != expected_length {
            return Err(format!(
                "checkpoint length {length} does not match envelope payload {expected_length}"
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(&header_bytes);
        let mut buffer = vec![0u8; 4 * 1024 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| format!("cannot read checkpoint: {error}"))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let actual = hex::encode(hasher.finalize());
        if actual != self.checkpoint_sha256 {
            return Err(format!(
                "checkpoint SHA-256 {actual} does not match manifest {}",
                self.checkpoint_sha256
            ));
        }
        if header.revision != self.checkpoint_revision {
            return Err(format!(
                "checkpoint revision {} does not match manifest {}",
                header.revision, self.checkpoint_revision
            ));
        }
        Ok(())
    }
}

/// One `eosio` `producers`-table row as restored from checkpoint state:
/// the block-signing key bound to a producer name. (`eosio.system` holds no
/// such table on XPR mainnet — the account does not exist there; the live
/// schedule table is code `eosio`, scope `eosio`.)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StateProducerKey {
    pub key: [u8; 33],
    pub is_active: bool,
    /// Vote weight as recorded on-chain. Quorum math runs over the
    /// transported roster's integer weights, not this float; it is exposed
    /// so roster builders start from the same source of truth.
    pub total_votes: f64,
}

/// Decode one `producer_info` row in Leap 5.0.3 `fc::raw` layout: owner,
/// `total_votes`, key type, 33-byte key, `is_active`, url, unpaid blocks,
/// last claim time, location. XPR mainnet rows carry NO authority tail
/// (verified live against mainnet: 8 fields, 90 bytes), so the schedule
/// key is taken as the signing key after a K1 validity gate — the same
/// rule the ceremony contract's `init` enforces. Vote weights are consumed
/// but not returned: they drift every block between the roster reference
/// and the checkpoint, so the cross-check binds names to keys and leaves
/// weights to the quorum math over the transported roster. `finish`
/// enforces exact consumption, so any future system-contract field
/// addition fails this decoder loudly instead of silently changing shape.
fn decode_producer_info_row(bytes: &[u8]) -> Result<(u64, StateProducerKey), XprImportError> {
    let mut row = RowCursor::new(bytes);
    let owner = row.u64()?;
    let total_votes = f64::from_le_bytes(row.fixed::<8>()?);
    if row.varuint()? != 0 {
        return Err(bad("XPR producer uses a non-K1 signing key"));
    }
    let key = row.fixed::<33>()?;
    let is_active = row.bool()?;
    let _url = row.bytes()?;
    let _unpaid_blocks = row.u32()?;
    let _last_claim_time = row.i64()?;
    let _location = row.u16()?;
    row.finish()?;
    Ok((
        owner,
        StateProducerKey {
            key,
            is_active,
            total_votes,
        },
    ))
}

/// Derive the producer-name to signing-key map from restored checkpoint
/// state (code `eosio`, scope `eosio`, table `producers` — the live XPR
/// schedule table, verified against mainnet). Returns an empty map when the
/// table is absent, which only happens for synthetic fixtures: real XPR
/// checkpoints always carry the schedule table.
pub fn migration_state_producer_keys(
    db: &Database,
) -> Result<BTreeMap<u64, StateProducerKey>, String> {
    use std::str::FromStr;
    let system = pulsevm_name::Name::from_str("eosio")
        .map_err(|e| format!("invalid system account name: {e}"))?
        .as_u64();
    let producers = pulsevm_name::Name::from_str("producers")
        .map_err(|e| format!("invalid producers table name: {e}"))?
        .as_u64();
    let mut map = BTreeMap::new();
    for (primary, value) in db.arena_table_range(system, system, producers) {
        let (owner, entry) = decode_producer_info_row(&value)
            .map_err(|e| format!("producers row {primary} undecodable: {e}"))?;
        if owner != primary {
            return Err(format!(
                "producers row {primary} carries a mismatched owner {owner}"
            ));
        }
        if map.insert(owner, entry).is_some() {
            return Err(format!("duplicate producers row for owner {owner}"));
        }
    }
    Ok(map)
}

/// Emit a starting-point halt roster from checkpoint state: every active
/// producer with the unit schedule weight. The ceremony roster must be this
/// whole active set, never a trimmed subset — the restore gate requires
/// exact set equality against checkpoint state, so the operator verifies
/// the template against the coordinated schedule (names, schedule keys,
/// version) and aborts on any divergence instead of trimming it: a subset
/// roster picks its own quorum denominator. `total_votes` is deliberately
/// ignored (it drifts every block); every entry weighs 1.
pub fn migration_halt_roster_template(
    db: &Database,
) -> Result<Vec<MigrationHaltRosterEntry>, String> {
    let mut roster = Vec::new();
    for (owner, entry) in migration_state_producer_keys(db)? {
        if !entry.is_active {
            continue;
        }
        let key = pulsevm_crypto::k1::K1PublicKey::from_compressed(&entry.key)
            .map_err(|e| format!("producers row {owner} holds an invalid key: {e:?}"))?;
        roster.push(MigrationHaltRosterEntry {
            producer: pulsevm_name::Name::new(owner).to_string(),
            key: key.to_string(),
            weight: pulsevm_chain_types::HaltWeight::MEMBER,
        });
    }
    Ok(roster)
}

/// Bind a transported halt roster to checkpoint content: every rostered
/// producer name must resolve to exactly the same signing key in the
/// restored state. Returns the number of bound entries. Weights are
/// deliberately not compared: they move every block, so a weight pinned
/// at the roster reference legitimately differs from checkpoint state.
/// `is_active` is likewise not enforced here (a producer may retire
/// between the reference and the checkpoint); activity enforcement
/// belongs to the on-chain ceremony that pins the roster.
///
/// This lenient form guards the legacy single-step commitments. The
/// two-step cutover uses [`check_halt_roster_matches_state`], which
/// additionally requires every declared member to be active with the same
/// key: a declaration naming only its signer verifies against itself, so
/// each member is key-anchored to checkpoint state.
pub fn check_halt_roster_against_state(
    roster: &[pulsevm_chain_types::HaltRosterEntry],
    state: &BTreeMap<u64, StateProducerKey>,
) -> Result<usize, String> {
    use std::str::FromStr;
    let mut matched = 0;
    for entry in roster {
        let name = pulsevm_name::Name::from_str(&entry.producer)
            .map_err(|e| format!("halt roster producer name invalid: {e}"))?
            .as_u64();
        let state_key = state.get(&name).ok_or_else(|| {
            format!(
                "halt roster producer {} is not present in checkpoint state",
                entry.producer
            )
        })?;
        if state_key.key != entry.key.compressed() {
            return Err(format!(
                "halt roster key for {} does not match checkpoint state",
                entry.producer
            ));
        }
        matched += 1;
    }
    Ok(matched)
}

/// Verify a manifest's halt commitment against the terminal block it names.
/// Both versions verify against the attached weighted roster under the
/// strict two-thirds quorum (version 2 additionally binds the migration
/// checkpoint). A manifest without a roster fails closed: the legacy
/// single-key path cannot prove the schedule agreed, so it promotes
/// nothing. This is the same check the restore gate runs; the offline
/// verifier reuses it so a manifest can be validated without booting a
/// node.
pub fn verify_migration_halt_commitment(
    manifest: &MigrationManifest,
    height: u32,
    block_id: &[u8; 32],
    checkpoint_sha256: &[u8; 32],
) -> Result<(), String> {
    use pulsevm_chain_types::HaltCommitment;
    let commitment = manifest
        .halt_commitment
        .as_ref()
        .ok_or_else(|| "migration manifest carries no halt commitment".to_string())?;
    let roster = manifest.roster_entries()?.ok_or_else(|| {
        "migration halt commitment carries no roster: single-key commitments prove nothing about the schedule"
            .to_string()
    })?;
    match commitment.version {
        HaltCommitment::VERSION => commitment
            .verify_weighted_quorum(height, block_id, &roster)
            .map_err(|e| format!("migration halt commitment rejected: {e}")),
        HaltCommitment::VERSION_V2 => commitment
            .verify_weighted_quorum_v2(height, block_id, checkpoint_sha256, &roster)
            .map_err(|e| format!("migration halt commitment rejected: {e}")),
        other => Err(format!("unsupported halt commitment version {other}")),
    }
}

/// Vote-timing rule for the two-step cutover: a commitment is only valid
/// inside its window. Votes are XPR transactions, so their inclusion height
/// is XPR consensus — unlike off-chain signature timestamps, which are
/// merely asserted. Declaration votes must land strictly before H (H stays
/// empty and the commitment is a genuine pre-commitment); confirmation
/// votes must land strictly after H (a confirmation references H_ID, which
/// cannot exist inside H itself). The freshness bound K and the deadline J
/// apply when the ceremony claims them. Sides without a recorded inclusion
/// are skipped: off-chain signatures carry no trustworthy timestamp.
pub fn check_halt_inclusion_window(
    height: u32,
    declaration_inclusion: Option<u32>,
    max_declaration_lag: Option<u32>,
    confirmation_inclusion: Option<u32>,
    max_confirmation_lag: Option<u32>,
) -> Result<(), String> {
    if let Some(inclusion) = declaration_inclusion {
        if inclusion >= height {
            return Err(format!(
                "declaration commitment at block {inclusion} does not predate cutover height {height}"
            ));
        }
        if let Some(max_lag) = max_declaration_lag
            && inclusion.saturating_add(max_lag) < height
        {
            return Err(format!(
                "declaration commitment at block {inclusion} is older than the ceremony window (H={height}, max lag {max_lag})"
            ));
        }
    }
    if let Some(inclusion) = confirmation_inclusion {
        if inclusion <= height {
            return Err(format!(
                "confirmation commitment at block {inclusion} does not postdate cutover height {height}"
            ));
        }
        if let Some(max_lag) = max_confirmation_lag
            && inclusion > height.saturating_add(max_lag)
        {
            return Err(format!(
                "confirmation commitment at block {inclusion} misses the ceremony deadline (H={height}, max lag {max_lag})"
            ));
        }
    }
    Ok(())
}

/// Verify on-chain cutover-contract evidence for the step-one declaration:
/// the captured singleton must be finalized on the verified declaration
/// digest, every scanned vote must be a rostered schedule key inside the
/// declaration window and under `expected_schedule_version`, and the
/// captured tally must match the recomputed signer weight under the strict
/// quorum. The attested schedule version must equal the expected (H's)
/// version: presence alone proves nothing, so a version the exporter merely
/// asserts without matching H fails closed, as does any vote from another
/// version. A manifest without contract evidence verifies nothing here:
/// the pair then requires a recorded declaration inclusion instead, so one
/// of the two always proves the quorum committed before H.
pub fn verify_migration_contract_evidence(
    manifest: &MigrationManifest,
    height: u32,
    roster: &[pulsevm_chain_types::HaltRosterEntry],
    declaration_digest: &[u8; 32],
    expected_schedule_version: u32,
) -> Result<(), String> {
    let Some(ceremony) = manifest.halt_contract_ceremony.as_ref() else {
        return Ok(());
    };
    if manifest.halt_schedule_version != Some(expected_schedule_version) {
        return Err(format!(
            "migration cutover contract evidence attests schedule version {:?} (expected H's version {expected_schedule_version})",
            manifest.halt_schedule_version
        ));
    }
    ceremony
        .verify(
            height,
            manifest.halt_max_declaration_lag,
            roster,
            declaration_digest,
            expected_schedule_version,
        )
        .map_err(|e| format!("migration cutover contract evidence rejected: {e}"))
}

/// Bound on post-H emptiness evidence. Bounds decode work at restore; a
/// genuinely longer pause needs a fresh export window, not a bigger
/// constant. The window is H+1 through the agreed pause head P (every
/// producer stops at P — there is no LIB wait and no tail past P), so a
/// normal cutover stages tens of blocks, never thousands.
pub const MAX_POST_H_BLOCKS: usize = 4096;

/// One decoded post-H header: exactly the fields the emptiness walk
/// checks, in `pulsevm_core::block` pack order (timestamp, producer,
/// confirmed, previous, roots, schedule version, schedule change flag,
/// header extensions, K1 signature, transaction count, block extensions).
/// Anything else in a post-H block fails closed, so the reader stays
/// minimal on purpose — extend it only with a matching fixture.
struct PostHeader {
    producer: u64,
    previous: [u8; 32],
    transaction_mroot: [u8; 32],
    schedule_version: u32,
    blockroot: [u8; 32],
    schedule_hash: [u8; 32],
    header_span: (usize, usize),
    signature_compact: [u8; 65],
}

fn read_u32_le(bytes: &[u8], pos: &mut usize, label: &str) -> Result<u32, String> {
    let end = pos
        .checked_add(4)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| format!("{label} ends mid-header (truncated u32)"))?;
    let value = u32::from_le_bytes(
        bytes[*pos..end]
            .try_into()
            .map_err(|_| format!("{label} ends mid-header (truncated u32)"))?,
    );
    *pos = end;
    Ok(value)
}

fn read_varuint32(bytes: &[u8], pos: &mut usize) -> Result<u32, String> {
    let mut value: u32 = 0;
    for shift in (0..35).step_by(7) {
        let byte = *bytes
            .get(*pos)
            .ok_or_else(|| "post-H block ends mid-header (truncated varuint)".to_string())?;
        *pos += 1;
        value |= u32::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or_else(|| "post-H block varuint overflows u32".to_string())?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("post-H block varuint overflows u32".to_string())
}

fn read_exact<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], String> {
    let end = pos
        .checked_add(len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| "post-H block ends mid-header (truncated field)".to_string())?;
    let slice = &bytes[*pos..end];
    *pos = end;
    Ok(slice)
}

/// Decode one packed post-H signed block, enforcing the emptiness shape:
/// no schedule change (inline or extension), K1 producer signature, no
/// transactions, no block extensions. Returns the header view, the block's
/// Leap-stated id from the end of the entry (which the walk recomputes
/// from the header and requires to match), and the total bytes consumed;
/// trailing bytes fail at the call site.
/// Shared entry prefix: blockroot root, pending schedule hash, header
/// (rotations and schedule-change extensions are policed for both layouts —
/// a rotation at H changes the set the ceremony froze just as one in the
/// window does), and the K1 producer signature. Post-H entries append counts
/// plus the block id; the H entry appends only the block id, because H
/// itself is an ordinary source-chain block that may carry traffic.
fn read_entry_prefix(packed: &[u8], label: &str) -> Result<(PostHeader, usize), String> {
    let mut pos = 0;
    // The record path leads each entry with the two signature inputs the
    // header cannot supply: the blockroot root and the pending schedule
    // hash for this height.
    let blockroot: [u8; 32] = read_exact(packed, &mut pos, 32)?
        .try_into()
        .map_err(|_| format!("{label} ends mid-blockroot (truncated root)"))?;
    let schedule_hash: [u8; 32] = read_exact(packed, &mut pos, 32)?
        .try_into()
        .map_err(|_| format!("{label} ends mid-schedule-hash (truncated hash)"))?;
    let header_start = pos;
    let _timestamp = read_u32_le(packed, &mut pos, label)?;
    let producer = {
        let raw = read_exact(packed, &mut pos, 8)?;
        u64::from_le_bytes(
            raw.try_into()
                .map_err(|_| format!("{label} ends mid-header (truncated producer)"))?,
        )
    };
    let _confirmed = read_exact(packed, &mut pos, 2)?;
    let previous: [u8; 32] = read_exact(packed, &mut pos, 32)?
        .try_into()
        .map_err(|_| format!("{label} ends mid-header (truncated previous)"))?;
    let transaction_mroot: [u8; 32] = read_exact(packed, &mut pos, 32)?
        .try_into()
        .map_err(|_| format!("{label} ends mid-header (truncated transaction mroot)"))?;
    let _action_mroot = read_exact(packed, &mut pos, 32)?;
    let schedule_version = read_u32_le(packed, &mut pos, label)?;
    let has_schedule_change = read_exact(packed, &mut pos, 1)?[0] != 0;
    if has_schedule_change {
        return Err(format!("{label} carries a producer schedule change"));
    }
    let extension_count = read_varuint32(packed, &mut pos)?;
    for _ in 0..extension_count {
        let id = {
            let raw = read_exact(packed, &mut pos, 2)?;
            u16::from_le_bytes(
                raw.try_into()
                    .map_err(|_| format!("{label} ends mid-header (truncated extension id)"))?,
            )
        };
        let len = read_varuint32(packed, &mut pos)? as usize;
        let _payload = read_exact(packed, &mut pos, len)?;
        // Extension 1 is the producer-schedule change: a rotation inside
        // the window changes the set the ceremony froze.
        if id == 1 {
            return Err(format!("{label} carries a producer schedule change"));
        }
    }
    let header_end = pos;
    let tag = read_exact(packed, &mut pos, 1)?[0];
    if tag != 0 {
        return Err(format!("{label} carries a non-K1 producer signature"));
    }
    let signature_compact: [u8; 65] = read_exact(packed, &mut pos, 65)?
        .try_into()
        .map_err(|_| format!("{label} ends mid-signature (truncated compact)"))?;
    Ok((
        PostHeader {
            producer,
            previous,
            transaction_mroot,
            schedule_version,
            blockroot,
            schedule_hash,
            header_span: (header_start, header_end),
            signature_compact,
        },
        pos,
    ))
}

fn read_post_block(packed: &[u8]) -> Result<(PostHeader, [u8; 32], usize), String> {
    let (header, mut pos) = read_entry_prefix(packed, "post-H block")?;
    let transaction_count = read_varuint32(packed, &mut pos)?;
    if transaction_count != 0 {
        return Err("post-H block is not empty: it carries transactions".to_string());
    }
    let extension_bytes = read_varuint32(packed, &mut pos)?;
    if extension_bytes != 0 {
        return Err("post-H block carries block extensions".to_string());
    }
    // The entry ends with the block's Leap-stated id, which the gate
    // recomputes from the header (Leap's formula) and requires to match.
    let block_id: [u8; 32] = read_exact(packed, &mut pos, 32)?
        .try_into()
        .map_err(|_| "post-H block ends mid-id (truncated block id)".to_string())?;
    Ok((header, block_id, pos))
}

/// The H entry carries no counts — H may carry traffic, so the counts would
/// name transactions the entry does not stage. The entry is exactly the
/// shared prefix plus the block id; anything trailing fails closed.
fn read_halt_block_entry(packed: &[u8]) -> Result<(PostHeader, [u8; 32]), String> {
    const LABEL: &str = "cutover block";
    let (header, pos) = read_entry_prefix(packed, LABEL)?;
    if pos + 32 != packed.len() {
        return Err(format!(
            "{LABEL} entry is not exactly prefix plus block id ({} trailing bytes)",
            packed.len().saturating_sub(pos + 32)
        ));
    }
    let block_id: [u8; 32] = packed[pos..pos + 32]
        .try_into()
        .map_err(|_| format!("{LABEL} ends mid-id (truncated block id)"))?;
    Ok((header, block_id))
}

/// Entry authentication shared by the H entry and the post-H window (see
/// [`verify_migration_post_chain`]): packed entry layout, the recorded
/// schedule key map, and Leap's true signature digest.
/// The recorded schedule as a producer-name to signing-key map: the H
/// entry and every post-H header resolve producers against it, so both
/// compare against the same set the pair verifier matches to the
/// declaration. The recorded schedule is a unit-weight set; anything else
/// is an exporter moving the denominator.
fn recorded_schedule_key_map(
    recorded: &[MigrationHaltRosterEntry],
) -> Result<std::collections::BTreeMap<String, pulsevm_crypto::k1::K1PublicKey>, String> {
    let mut schedule_keys = std::collections::BTreeMap::new();
    for entry in recorded {
        if entry.weight != pulsevm_chain_types::HaltWeight::MEMBER {
            return Err(format!(
                "recorded schedule weight for {} is not the schedule weight 1",
                entry.producer
            ));
        }
        let key = pulsevm_crypto::k1::K1PublicKey::from_string(&entry.key).map_err(|e| {
            format!(
                "recorded schedule key for {} invalid: {e:?}",
                entry.producer
            )
        })?;
        if schedule_keys.insert(entry.producer.clone(), key).is_some() {
            return Err(format!("recorded schedule names {} twice", entry.producer));
        }
    }
    Ok(schedule_keys)
}

/// Leap's producer signature digest for one packed entry
/// (`block_header_state::sig_digest`): sha256(sha256(header_digest ||
/// blockroot) || schedule_hash), plus the header digest itself for the
/// block-id derivation. Verifying the bare header digest instead would
/// accept signatures no Leap node produced — and hashing the header bytes
/// with the root instead of the header digest would reject the signatures
/// Leap nodes produce.
fn leap_entry_digest(header: &PostHeader, header_bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    let header_digest = pulsevm_crypto::Digest::hash(header_bytes).0;
    let bound = {
        let mut digest_and_root = Vec::with_capacity(64);
        digest_and_root.extend_from_slice(&header_digest);
        digest_and_root.extend_from_slice(&header.blockroot);
        pulsevm_crypto::Digest::hash(&digest_and_root).0
    };
    let mut bound_and_schedule = Vec::with_capacity(64);
    bound_and_schedule.extend_from_slice(&bound);
    bound_and_schedule.extend_from_slice(&header.schedule_hash);
    let digest = pulsevm_crypto::Digest::hash(&bound_and_schedule).0;
    (header_digest, digest)
}

/// Verify the cutover block H entry: the packed H header must derive the
/// trusted H id, carry H's schedule version, introduce no schedule change,
/// and carry a producer signature — over Leap's true digest with the
/// entry's recorded root and schedule hash — that recovers to the recorded
/// schedule key for H's producer. The window opens on exactly the block
/// the confirmation binds; a substituted H fails here instead of anchoring
/// the proof. H may carry traffic (it is an ordinary source-chain block),
/// so the entry proves the anchor, not emptiness — only the post-H window
/// must be empty.
pub fn verify_migration_halt_block(
    manifest: &MigrationManifest,
    height: u32,
    block_id: &[u8; 32],
    schedule_version: u32,
) -> Result<u32, String> {
    let packed_hex = manifest.halt_h_block.as_ref().ok_or_else(|| {
        "migration cutover pair carries no cutover-block evidence: the window cannot open on an unattested H"
            .to_string()
    })?;
    let packed = hex::decode(packed_hex)
        .map_err(|e| format!("cutover block entry is not hexadecimal: {e}"))?;
    let (header, stated_id) =
        read_halt_block_entry(&packed).map_err(|e| format!("cutover block entry rejected: {e}"))?;
    let header_bytes = &packed[header.header_span.0..header.header_span.1];
    let (header_digest, digest) = leap_entry_digest(&header, header_bytes);
    // The entry must open on the trusted H: derive its id and require it
    // to equal the terminal block the confirmation binds.
    let mut derived_id = header_digest;
    derived_id[0..4].copy_from_slice(&height.to_be_bytes());
    if stated_id != derived_id {
        return Err("cutover block entry id does not derive from its header".to_string());
    }
    if &stated_id != block_id {
        return Err(
            "cutover block entry id does not match the terminal block the confirmation binds"
                .to_string(),
        );
    }
    // No emptiness check: H is an ordinary source-chain block and may
    // carry traffic — the entry proves the anchor (id, signature, version),
    // not the contents. Only the post-H window must be empty.
    if header.schedule_version != schedule_version {
        return Err(format!(
            "cutover block carries schedule version {} (expected {schedule_version})",
            header.schedule_version
        ));
    }
    let Some(recorded) = manifest.halt_schedule.as_ref() else {
        return Err("migration cutover pair carries no recorded schedule".to_string());
    };
    let schedule_keys = recorded_schedule_key_map(recorded)?;
    let producer_name = pulsevm_name::Name::new(header.producer).to_string();
    let scheduled_key = schedule_keys.get(&producer_name).ok_or_else(|| {
        format!("cutover block producer {producer_name} is not in the recorded schedule")
    })?;
    let signature = pulsevm_crypto::k1::K1Signature::from_compact65(&header.signature_compact);
    let recovered = signature
        .recover(&digest)
        .map_err(|e| format!("cutover block signature unrecoverable: {e:?}"))?;
    if recovered != *scheduled_key {
        return Err(format!(
            "cutover block is not signed by the scheduled key for {producer_name}"
        ));
    }
    // The entry's header bytes lead with the Leap timestamp slot (pack
    // order timestamp[4] | producer[8] | ...): return it so the memo
    // inclusion proof can require every recorded memo account to predate H.
    let slot_bytes: [u8; 4] = header_bytes
        .get(..4)
        .and_then(|slot| slot.try_into().ok())
        .ok_or_else(|| "cutover block entry header has no timestamp slot".to_string())?;
    Ok(u32::from_le_bytes(slot_bytes))
}

/// Committee-membership pin for the two-step cutover (the light-client
/// rule): the declared set must equal the recorded schedule exactly, both
/// ways, with matching schedule keys. The recorded schedule comes from H's
/// header state, captured at the freeze instant and bound to the trusted H
/// id (which the checkpoint's snapshot shares) — never from the producers
/// table, which carries every active row while the schedule
/// names only the committee. The forward direction closes key substitution
/// (a declaration key differing from the schedule key fails); the reverse
/// direction closes the standby-subset attack (a subset naming only some
/// scheduled producers fails, so no minority passes over a denominator it
/// chose). Neither the version pin nor the count quorum can substitute for
/// this: a subset copies H's version and picks its own denominator.
/// Weights are not compared: every member weighs 1 by construction
/// (enforced at declaration parse and at record time), so there is no
/// drift to pin.
pub fn check_declaration_matches_recorded_schedule(
    declaration: &pulsevm_chain_types::HaltDeclaration,
    schedule_keys: &std::collections::BTreeMap<String, pulsevm_crypto::k1::K1PublicKey>,
) -> Result<usize, String> {
    let mut declared: Vec<(String, pulsevm_crypto::k1::K1PublicKey)> = Vec::new();
    for member in &declaration.validator_set {
        let key = pulsevm_crypto::k1::K1PublicKey::from_string(&member.key).map_err(|e| {
            format!(
                "halt declaration key for {} invalid: {e:?}",
                member.producer
            )
        })?;
        declared.push((member.producer.clone(), key));
    }
    declared.sort();
    let mut recorded_sorted: Vec<(String, pulsevm_crypto::k1::K1PublicKey)> = schedule_keys
        .iter()
        .map(|(producer, key)| (producer.clone(), *key))
        .collect();
    recorded_sorted.sort();
    if declared != recorded_sorted {
        return Err("migration halt declaration does not match the recorded schedule".to_string());
    }
    Ok(declared.len())
}

/// Memo-vehicle inclusion proof: the declaration digest must re-decode
/// from the recorded memo account names, and every recorded account must
/// predate H. The names are deterministic from the digest (`h` + one round
/// letter + hex nibbles mapped to `a`–`p`), so re-decoding proves the
/// declaration text is committed on-chain — not merely asserted in the
/// manifest — and the slot bound proves it landed before H instead of in
/// it. A manifest without memo accounts (contract vehicle, legacy
/// commitments) verifies nothing here: the contract fragment carries its
/// own vote heights, and legacy paths carry no declaration. Returns the
/// account count. Existence in checkpoint state is checked separately by
/// [`verify_memo_accounts_exist`], where the state is available: names that
/// decode but name no account fail there, not here.
pub fn verify_migration_memo_accounts(
    manifest: &MigrationManifest,
    declaration_digest: &[u8; 32],
    h_slot: u32,
) -> Result<usize, String> {
    let Some(accounts) = manifest.halt_memo_accounts.as_ref() else {
        return Ok(0);
    };
    if accounts.is_empty() {
        return Err(
            "migration memo inclusion records no accounts: stage the declaration accounts or drop the record"
                .to_string(),
        );
    }
    let mut nibbles = String::with_capacity(64);
    for account in accounts {
        let name = account.name.as_str();
        // `h` + one round letter + the digest nibbles mapped a-p.
        let mut chars = name.chars();
        let (Some('h'), Some(_round), rest) = (chars.next(), chars.next(), chars.as_str()) else {
            return Err(format!(
                "migration memo account {name} does not carry the declaration digest"
            ));
        };
        if rest.is_empty() || !rest.bytes().all(|b| (b'a'..=b'p').contains(&b)) {
            return Err(format!(
                "migration memo account {name} does not carry the declaration digest"
            ));
        }
        for byte in rest.bytes() {
            let hex = if byte <= b'j' {
                b'0' + (byte - b'a')
            } else {
                b'a' + (byte - b'k')
            };
            nibbles.push(hex as char);
        }
        if account.created_slot >= h_slot {
            return Err(format!(
                "migration memo account {name} was created at slot {} (H is slot {h_slot}): the declaration must land before H",
                account.created_slot
            ));
        }
    }
    if nibbles.len() != 64 {
        return Err(format!(
            "migration memo accounts decode to {} hex nibbles, not the 64 of a declaration digest",
            nibbles.len()
        ));
    }
    if hex::decode(&nibbles).map_err(|e| format!("migration memo digest unreadable: {e}"))?
        != declaration_digest
    {
        return Err("migration memo accounts do not decode to the declaration digest".to_string());
    }
    Ok(accounts.len())
}

/// Checkpoint-state half of the memo inclusion proof: every recorded memo
/// account must exist in the restored state. The digest re-decode (see
/// [`verify_migration_memo_accounts`]) proves the names commit to the
/// declaration; this proves the named accounts are really on-chain — a
/// manifest that records fictional names fails here even when they decode.
/// Runs wherever restored state is available (restore gate, offline
/// verifier); manifests without memo accounts verify nothing and return 0.
pub fn verify_memo_accounts_exist(
    database: &Database,
    manifest: &MigrationManifest,
) -> Result<usize, String> {
    use std::str::FromStr;
    let Some(accounts) = manifest.halt_memo_accounts.as_ref() else {
        return Ok(0);
    };
    for memo in accounts {
        let owner = pulsevm_name::Name::from_str(&memo.name)
            .map_err(|e| format!("migration memo account {} invalid: {e}", memo.name))?;
        if !database.arena_account_exists(owner.as_u64()) {
            return Err(format!(
                "migration memo account {} does not exist in checkpoint state: the declaration landing is unproven",
                memo.name
            ));
        }
    }
    Ok(accounts.len())
}

/// Verify the post-H emptiness proof plus the recorded schedule: every
/// header hash-links from the trusted H id with ascending numbers, carries
/// an empty transaction root, introduces no schedule change, and is signed
/// by the recorded schedule key for its producer over Leap's true digest
/// (`sha256(sha256(sha256(header) || blockroot) || schedule_hash)`, recomputed
/// from the entry's recorded root and hash) — and the recorded schedule
/// equals the declared set exactly (see
/// [`check_declaration_matches_recorded_schedule`]). The entry's hash is
/// bound by the signature itself, not by a comparison: only the exact
/// (root, hash) pair Leap signed recovers to the roster key. Each entry
/// trails its block's Leap-stated id, which the walk recomputes from the
/// packed header (Leap's formula: sha256 of the header with the number
/// spliced in) and requires to match exactly. The staged
/// headers must cover exactly H+1 through `pause_height`, the agreed pause
/// head every producer stopped at: a proof that stops short leaves the
/// tail past the last staged header unproven, and a proof that runs past
/// the agreed head carries headers past the agreed stop. The pause
/// head must sit strictly past H: a pause exactly on H stages no proof and
/// cannot distinguish a frozen network from a bare anchor, so it fails
/// closed here and in the confirmation itself. Returns the attested pause
/// length. An absent proof or an absent schedule fails closed: unattested
/// windows do not boot.
pub fn verify_migration_post_chain(
    manifest: &MigrationManifest,
    declaration: &pulsevm_chain_types::HaltDeclaration,
    height: u32,
    block_id: &[u8; 32],
    schedule_version: u32,
    pause_height: u32,
) -> Result<usize, String> {
    if pause_height <= height {
        return Err(format!(
            "migration cutover pair attests pause head {pause_height} at or below cutover height {height}: the pause head must sit strictly past H"
        ));
    }
    let expected_len = (pause_height - height) as usize;
    let Some(blocks) = manifest.halt_post_blocks.as_ref() else {
        return Err("migration cutover pair carries no post-H emptiness evidence".to_string());
    };
    let Some(recorded) = manifest.halt_schedule.as_ref() else {
        return Err("migration cutover pair carries no recorded schedule".to_string());
    };
    if blocks.len() > MAX_POST_H_BLOCKS {
        return Err(format!(
            "migration cutover pair attests {} post-H blocks (limit {MAX_POST_H_BLOCKS})",
            blocks.len()
        ));
    }
    // Exact coverage of the attested pause head: stopping short would
    // leave H+len+1..P unproven, running long would stage headers past
    // what the quorum attested. P is the agreed stop every producer
    // halted at — not an observed tip — so the covered window is exactly
    // H+1..P by construction, and the 15-of-21 confirmation over H_ID
    // stands in for Leap finality instead of a LIB wait.
    if blocks.len() != expected_len {
        return Err(format!(
            "migration cutover pair stages {} post-H blocks but the quorum attested pause head {pause_height} (H={height}): the proof must cover exactly H+1 through the attested pause head",
            blocks.len()
        ));
    }
    // The recorded schedule is a unit-weight set; anything else is an
    // exporter moving the denominator.
    let schedule_keys = recorded_schedule_key_map(recorded)?;
    // Declared set == recorded schedule, both ways: the declaration must
    // name the recorded set exactly, so neither side can smuggle a member.
    // This is the committee-membership pin (it replaced the producers-table
    // cross-check: the table carries every active row while the schedule
    // names only the committee, so the table cannot authenticate the set).
    check_declaration_matches_recorded_schedule(declaration, &schedule_keys)?;
    // No hash pin on the staged pending schedule: with no staged change
    // Leap serves the EMPTY pending schedule, whose hash cannot equal the
    // active roster's (proven against live header states). The producer
    // signature binds the exact (root, hash) pair below — only the true
    // pair recovers to the roster key — so a forged state fails at
    // recovery, not at a comparison.
    let mut expected_num = height
        .checked_add(1)
        .ok_or_else(|| "migration cutover height overflows u32".to_string())?;
    let mut expected_previous = *block_id;
    for packed_hex in blocks {
        let packed =
            hex::decode(packed_hex).map_err(|e| format!("post-H block is not hexadecimal: {e}"))?;
        let (header, stated_id, consumed) = read_post_block(&packed)
            .map_err(|e| format!("post-H block {expected_num} rejected: {e}"))?;
        if consumed != packed.len() {
            return Err(format!(
                "post-H block {expected_num} has {} trailing bytes",
                packed.len() - consumed
            ));
        }
        let parent_num = u32::from_be_bytes(
            header.previous[0..4]
                .try_into()
                .map_err(|_| format!("post-H block {expected_num} has a malformed previous id"))?,
        );
        if parent_num.checked_add(1) != Some(expected_num) {
            return Err(format!(
                "post-H block {expected_num} does not follow its parent height"
            ));
        }
        if header.previous != expected_previous {
            return Err(format!(
                "post-H block {expected_num} does not hash-link to its parent"
            ));
        }
        if header.transaction_mroot != [0u8; 32] {
            return Err(format!(
                "post-H block {expected_num} is not empty: non-empty transaction root"
            ));
        }
        // The window must not rotate the schedule: the version is H's,
        // pinned by the caller, on every header.
        if header.schedule_version != schedule_version {
            return Err(format!(
                "post-H block {expected_num} carries schedule version {} (expected {schedule_version})",
                header.schedule_version
            ));
        }
        let producer_name = pulsevm_name::Name::new(header.producer).to_string();
        let scheduled_key = schedule_keys.get(&producer_name).ok_or_else(|| {
            format!("post-H block {expected_num} producer {producer_name} is not in the recorded schedule")
        })?;
        let header_bytes = &packed[header.header_span.0..header.header_span.1];
        let (header_digest, digest) = leap_entry_digest(&header, header_bytes);
        let signature = pulsevm_crypto::k1::K1Signature::from_compact65(&header.signature_compact);
        let recovered = signature
            .recover(&digest)
            .map_err(|e| format!("post-H block {expected_num} signature unrecoverable: {e:?}"))?;
        if recovered != *scheduled_key {
            return Err(format!(
                "post-H block {expected_num} is not signed by the scheduled key for {producer_name}"
            ));
        }
        // The block id is derived, never carried: Leap's formula hashes
        // the packed header and splices the block number into the first
        // four bytes. The stated trailing id must equal the recomputation
        // exactly — checking only the embedded number would let an empty
        // sibling ride under the real block's number while the real,
        // non-empty block hides beside the proof.
        let mut derived_id = header_digest;
        derived_id[0..4].copy_from_slice(&expected_num.to_be_bytes());
        if stated_id != derived_id {
            return Err(format!(
                "post-H block {expected_num} id does not derive from its header"
            ));
        }
        expected_previous = stated_id;
        expected_num = expected_num
            .checked_add(1)
            .ok_or_else(|| "post-H block height overflows u32".to_string())?;
    }
    Ok(blocks.len())
}

/// Verify the two-step cutover pair: the declaration must carry a quorum
/// of the declared set over the cutover height, the confirmation must chain
/// that exact declaration to the terminal block, the checkpoint, this
/// chain's id, and the configured platform id, and an attached transport
/// roster — when present — must match the declared set entry-wise so the
/// two encodings cannot diverge. The attested schedule version must equal
/// `header_schedule_version` (H's version) unconditionally, the manifest
/// must attest no proposed schedule in the checkpoint, the staged H entry
/// must derive the terminal block with a recorded-schedule producer
/// signature, and the staged post-H headers must cover exactly
/// H+1 through the confirmation's pause head, which must sit strictly past
/// H. Recorded inclusion heights are window-checked via
/// [`check_halt_inclusion_window`];
/// attached contract evidence is replayed via
/// [`verify_migration_contract_evidence`] with every vote pinned to
/// `header_schedule_version`.
/// Pre-commitment timing must be provable one of two ways: the on-chain
/// ceremony (per-vote timing), or a recorded declaration inclusion (the
/// digest on-chain before H, as the memo and msig vehicles record). A pair
/// with neither fails closed — off-chain signatures alone say nothing
/// about when they were made.
/// Returns the declared set. Committee membership is pinned here, not
/// against the producers table: the declaration must equal the recorded
/// schedule exactly (both ways, same keys), and that schedule comes from
/// H's header state, captured at the freeze instant — the table carries
/// every active row while the schedule names only the committee. This is
/// the same check the
/// restore gate runs; the offline verifier reuses it so a manifest can be
/// validated without booting a node. The restore gate always configures a
/// platform id (`Some`); `None` is the legacy and offline-tolerant path (a
/// confirmation that binds a platform still has its signatures checked,
/// but the id itself goes unconfirmed — the gate remains the enforcer,
/// since only boot config knows the real id).
pub fn verify_migration_halt_pair(
    manifest: &MigrationManifest,
    height: u32,
    block_id: &[u8; 32],
    checkpoint_sha256: &[u8; 32],
    new_chain_id: &[u8; 32],
    header_schedule_version: u32,
    platform_chain_id: Option<&[u8; 32]>,
) -> Result<Vec<pulsevm_chain_types::HaltRosterEntry>, String> {
    let declaration = manifest.halt_declaration.as_ref().ok_or_else(|| {
        "two-step cutover requires a halt declaration in the migration manifest".to_string()
    })?;
    let declaration_digest = declaration
        .verify(height)
        .map_err(|e| format!("migration halt declaration rejected: {e}"))?;
    let roster = declaration
        .roster()
        .map_err(|e| format!("migration halt declaration set invalid: {e}"))?;
    // The transport roster is inspectability sugar over the same set: when
    // the exporter attaches both, they must agree exactly.
    if let Some(transport) = manifest.roster_entries()?
        && transport != roster
    {
        return Err("migration halt roster does not match the declared validator set".to_string());
    }
    let confirmation = manifest.halt_confirmation.as_ref().ok_or_else(|| {
        "two-step cutover requires a halt confirmation chaining the declaration".to_string()
    })?;
    confirmation
        .verify(
            &declaration_digest,
            &roster,
            height,
            block_id,
            checkpoint_sha256,
            new_chain_id,
            platform_chain_id,
        )
        .map_err(|e| format!("migration halt confirmation rejected: {e}"))?;
    // The version pin is unconditional (memo and contract vehicles alike):
    // the attested schedule version must equal H's header version, so a
    // divergent schedule fails closed as a stale version even when no
    // contract evidence is attached.
    if manifest.halt_schedule_version != Some(header_schedule_version) {
        return Err(format!(
            "migration cutover pair attests schedule version {:?} (expected H's version {header_schedule_version})",
            manifest.halt_schedule_version
        ));
    }
    // A checkpoint taken mid-rotation would boot the new chain with a
    // pending proposal the ceremony never froze: only an explicit
    // export-time attestation of absence boots.
    if manifest.halt_proposed_schedule != Some(false) {
        return Err(format!(
            "migration cutover pair attests a proposed schedule {:?}: the checkpoint must carry no pending proposal",
            manifest.halt_proposed_schedule
        ));
    }
    // The cutover block itself is signature-checked first: the window must
    // open on exactly the block the confirmation binds, with an empty root
    // and a producer signature from the recorded schedule.
    let h_slot = verify_migration_halt_block(manifest, height, block_id, header_schedule_version)?;
    // Memo-vehicle inclusion proof: the digest re-decodes from the recorded
    // memo names and every recorded account predates H — the declaration
    // provably landed on-chain before the cutoff, not as an asserted
    // number. (Existence in checkpoint state is checked at restore, where
    // the state is available.)
    verify_migration_memo_accounts(manifest, &declaration_digest, h_slot)?;
    // Post-H emptiness plus the recorded schedule: every header hash-links
    // from H, carries an empty root, and is signed by a recorded schedule
    // key, the recorded schedule equals the declared set, and the staged
    // headers cover exactly H+1 through the confirmation's pause head —
    // the highest head the quorum attested, strictly past H. A fleet that
    // did not keep the window empty cannot produce this evidence, and a
    // proof that stops short of the quorum's own observation fails closed.
    verify_migration_post_chain(
        manifest,
        declaration,
        height,
        block_id,
        header_schedule_version,
        confirmation.pause_height,
    )?;
    check_halt_inclusion_window(
        height,
        manifest.halt_declaration_inclusion,
        manifest.halt_max_declaration_lag,
        manifest.halt_confirmation_inclusion,
        manifest.halt_max_confirmation_lag,
    )?;
    verify_migration_contract_evidence(
        manifest,
        height,
        &roster,
        &declaration_digest,
        header_schedule_version,
    )?;
    // Pre-commitment timing must be provable: either the on-chain ceremony
    // replays the quorum's votes before H, or the declaration digest was
    // recorded on-chain (memo / msig execution) before H. Off-chain
    // signatures alone say nothing about when they were made.
    if manifest.halt_contract_ceremony.is_none() && manifest.halt_declaration_inclusion.is_none() {
        return Err("migration halt declaration has no pre-commitment timing evidence: attach the on-chain cutover ceremony or record the declaration inclusion block".to_string());
    }
    Ok(roster)
}

/// Schedule-version offset in a packed `signed_block` prefix, in this
/// codebase's pack order (which the id check proves reproduces the wire
/// layout bit-for-bit): timestamp[4] | producer[8] | confirmed[u16] |
/// previous[32] | transaction_mroot[32] | action_mroot[32] |
/// schedule_version[u32 LE] — the version starts at byte 110.
///
/// The restore gate reads H's version from the decoded source block; the
/// offline verifier reuses this prefix parse because it cannot decode full
/// blocks. A wrong offset fails closed (the version will not match H), so
/// this helper can only refuse, never admit — and a golden test pins the
/// offset against a decoded block in the controller migration tests.
pub fn packed_source_block_schedule_version(packed_hex: &str) -> Result<u32, String> {
    const OFFSET: usize = 4 + 8 + 2 + 32 + 32 + 32;
    const PREFIX: usize = OFFSET + 4;
    let bytes =
        hex::decode(packed_hex).map_err(|e| format!("source block is not hexadecimal: {e}"))?;
    if bytes.len() < PREFIX {
        return Err(format!(
            "source block prefix is {} bytes, need at least {PREFIX} for the schedule version",
            bytes.len()
        ));
    }
    let raw: [u8; 4] = bytes[OFFSET..PREFIX]
        .try_into()
        .map_err(|_| "source block schedule version slice is not 4 bytes".to_string())?;
    Ok(u32::from_le_bytes(raw))
}

/// A malformed or unsupported XPR state-history input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XprImportError(String);

impl fmt::Display for XprImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for XprImportError {}

/// JSON emitted by the XPR chainbase migration-sidecar exporter.
///
/// XPR's SHiP `generated_transaction_v0` table row contains identity and
/// payload bytes, but not its three scheduler timestamps. A source-node
/// sidecar must read those fields from the same accepted block and write this
/// format. Numeric names stay numeric so comparison with SHiP is lossless;
/// `sender_id` is decimal because JSON cannot represent `uint128` precisely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredTransactionSidecar {
    pub version: u16,
    pub source_block_id: String,
    /// Optional source-chain identity and omitted chainbase fields. Version 1
    /// sidecars produced before full-state parity only contain transactions;
    /// current exporters populate these arrays so migration can preserve the
    /// fields that SHiP intentionally projects away.
    #[serde(default)]
    pub source_chain_id: Option<String>,
    #[serde(default)]
    pub account_metadata: Vec<AccountMetadataSidecarRow>,
    #[serde(default)]
    pub code: Vec<CodeSidecarRow>,
    #[serde(default)]
    pub permissions: Vec<PermissionSidecarRow>,
    /// Counter from `dynamic_global_property_object`, which SHiP omits.
    pub global_action_sequence: u64,
    /// Complete `transaction_object` replay-protection set, which SHiP omits.
    pub input_transactions: Vec<InputTransactionSidecarRow>,
    #[serde(default)]
    pub transactions: Vec<DeferredTransactionSidecarRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountMetadataSidecarRow {
    pub name: u64,
    pub recv_sequence: u64,
    pub auth_sequence: u64,
    pub code_sequence: u64,
    pub abi_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeSidecarRow {
    pub code_hash: String,
    pub vm_type: u8,
    pub vm_version: u8,
    pub code_ref_count: u64,
    pub first_block_used: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionSidecarRow {
    pub owner: u64,
    pub name: u64,
    pub last_used: i64,
}

/// One XPR chainbase `transaction_object` replay-protection record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputTransactionSidecarRow {
    pub trx_id: String,
    /// XPR `time_point_sec` value in whole seconds since the Unix epoch.
    pub expiration: u32,
}

/// One complete XPR chainbase `generated_transaction_object` record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredTransactionSidecarRow {
    pub sender: u64,
    pub sender_id: String,
    pub payer: u64,
    pub trx_id: String,
    /// XPR `time_point` values in microseconds since the Unix epoch.
    pub delay_until: i64,
    pub expiration: i64,
    pub published: i64,
    /// Hex-encoded `packed_transaction` bytes, as stored by XPR chainbase.
    pub packed_trx: String,
}

impl DeferredTransactionSidecar {
    pub const VERSION: u16 = 2;

    /// Parse and normalize a sidecar before it is compared with SHiP rows.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, XprImportError> {
        let sidecar: Self = serde_json::from_slice(bytes).map_err(|error| {
            bad(format!(
                "invalid deferred-transaction sidecar JSON: {error}"
            ))
        })?;
        if sidecar.version != Self::VERSION {
            return Err(bad(format!(
                "unsupported deferred-transaction sidecar version {} (expected {})",
                sidecar.version,
                Self::VERSION
            )));
        }
        decode_block_id(&sidecar.source_block_id)?;
        if let Some(source_chain_id) = &sidecar.source_chain_id {
            decode_block_id(source_chain_id)
                .map_err(|error| bad(format!("invalid source chain id: {error}")))?;
        }
        let mut metadata_names = HashSet::new();
        for row in &sidecar.account_metadata {
            if !metadata_names.insert(row.name) {
                return Err(bad(format!(
                    "duplicate account_metadata sidecar row for {}",
                    row.name
                )));
            }
        }
        let mut code_keys = HashSet::new();
        for row in &sidecar.code {
            let hash = decode_block_id(&row.code_hash)
                .map_err(|error| bad(format!("invalid code sidecar hash: {error}")))?;
            if !code_keys.insert((hash, row.vm_type, row.vm_version)) {
                return Err(bad("duplicate code sidecar row"));
            }
        }
        let mut permission_keys = HashSet::new();
        for row in &sidecar.permissions {
            if !permission_keys.insert((row.owner, row.name)) {
                return Err(bad("duplicate permission sidecar row"));
            }
        }
        let mut input_transaction_ids = HashSet::new();
        for row in &sidecar.input_transactions {
            let trx_id = decode_block_id(&row.trx_id)
                .map_err(|error| bad(format!("invalid input transaction id: {error}")))?;
            if !input_transaction_ids.insert(trx_id) {
                return Err(bad("duplicate input transaction sidecar row"));
            }
        }
        for row in &sidecar.transactions {
            sidecar_key(row)?;
        }
        Ok(sidecar)
    }
}

/// Unix microseconds of the Antelope epoch (2000-01-01T00:00:00Z): block
/// slots count 500ms steps from here, while deferred `delay_until` and
/// `expiration` are Unix `time_point` microseconds. The offset converts
/// staged post-H header times into the deferred rows' clock.
pub const ANTELOPE_EPOCH_UNIX_MICROS: i64 = 946_684_800_000_000;

/// Convert an Antelope block slot (500ms steps since the Antelope epoch)
/// to Unix microseconds. Saturates instead of wrapping: the result feeds
/// a comparison, never a hash, and a hostile slot must refuse, not wrap.
pub fn antelope_slot_to_unix_micros(slot: u32) -> i64 {
    const HALF_SECOND_MICROS: i64 = 500_000;
    (slot as i64)
        .saturating_mul(HALF_SECOND_MICROS)
        .saturating_add(ANTELOPE_EPOCH_UNIX_MICROS)
}

/// Export-time deferred-transaction inventory: no migrated deferred
/// transaction may be due in the (H, P] pause window. Any row executable
/// on a post-H block would set the block's `transaction_mroot` and fail
/// the boot closed at the emptiness gate — correct, but only after the
/// ceremony, the snapshot, and the freeze have all run. This check runs
/// where the exporter stages the window (the attach tool and the offline
/// verifier) and fails closed pre-H instead, naming the offending sender
/// and transaction.
///
/// A row fires in-window when its delay has elapsed by the pause head
/// (`delay_until <= window_end_us`) while it is still unexpired at the
/// window start (`expiration >= window_start_us`): that covers both live
/// executions and expired-receipt retirements (an `expired` receipt still
/// lands in the block, so the root still moves). Rows due after P, and
/// rows already expired before the window, cross the boundary by design
/// and are accepted here — they execute (or stay retired) on the new
/// chain under its own scheduler.
pub fn check_no_deferred_due_in_window(
    transactions: &[DeferredTransactionSidecarRow],
    window_start_us: i64,
    window_end_us: i64,
) -> Result<(), String> {
    if window_end_us < window_start_us {
        return Err(format!(
            "deferred inventory window ends ({window_end_us}) before it starts ({window_start_us}): refusing an unorderable window"
        ));
    }
    for row in transactions {
        if row.delay_until <= window_end_us && row.expiration >= window_start_us {
            return Err(format!(
                "deferred transaction {} (sender {}) is due in the pause window: delay_until {} expiration {} overlap [{window_start_us}, {window_end_us}] — cancel it pre-export or it fails the boot at the emptiness gate",
                row.trx_id, row.sender, row.delay_until, row.expiration
            ));
        }
    }
    Ok(())
}

/// Restore-side deferred-transaction inventory: no migrated deferred row
/// may be due in the staged (H, P] pause window. The export-time inventory
/// runs only when a sidecar is staged, but these are the rows actually
/// promoted — so the restore gate re-checks them straight from the manifest
/// window instead of trusting the export. A row due in-window would have
/// executed on a post-H block and set its `transaction_mroot`, which the
/// emptiness gate would then refuse; failing here names the row at boot.
pub fn check_no_arena_deferred_due_in_window(
    rows: &[crate::backend::DeferredTransaction],
    window_start_us: i64,
    window_end_us: i64,
) -> Result<(), String> {
    if window_end_us < window_start_us {
        return Err(format!(
            "deferred inventory window ends ({window_end_us}) before it starts ({window_start_us}): refusing an unorderable window"
        ));
    }
    for row in rows {
        if row.delay_until <= window_end_us && row.expiration >= window_start_us {
            return Err(format!(
                "migrated deferred transaction {} (sender {}) is due in the pause window: delay_until {} expiration {} overlap [{window_start_us}, {window_end_us}] — cancel it pre-export or the boot fails at the emptiness gate",
                hex::encode(row.trx_id),
                row.sender,
                row.delay_until,
                row.expiration
            ));
        }
    }
    Ok(())
}

/// Pause-window bounds straight from the manifest: H's Unix time from the
/// attached source-block slot, P's from the last staged post-H header slot
/// (offset past the 64-byte root/schedule-hash prefix). The restore gate
/// uses this for the deferred inventory, so the window never depends on an
/// optionally staged sidecar. A manifest without staged post-H headers has
/// no window: P must sit strictly past H, so that fails closed here.
pub fn manifest_pause_window_us(manifest: &MigrationManifest) -> Result<(i64, i64), String> {
    fn slot_at(hex_text: &str, prefix: usize, what: &str) -> Result<u32, String> {
        let bytes =
            hex::decode(hex_text).map_err(|error| format!("{what} is not hexadecimal: {error}"))?;
        if bytes.len() < prefix + 4 {
            return Err(format!("{what} is shorter than its timestamp slot"));
        }
        Ok(u32::from_le_bytes(
            bytes[prefix..prefix + 4]
                .try_into()
                .map_err(|_| format!("{what} timestamp is not 4 bytes"))?,
        ))
    }
    let source = manifest.source_block.as_deref().ok_or_else(|| {
        "halt proof requires an attached source block for the pause-window inventory".to_string()
    })?;
    let start = antelope_slot_to_unix_micros(slot_at(source, 0, "source block")?);
    let blocks = manifest.halt_post_blocks.as_ref().ok_or_else(|| {
        "migration cutover pair carries no post-H emptiness evidence for the pause-window inventory"
            .to_string()
    })?;
    let last = blocks.last().ok_or_else(|| {
        "migration cutover pair stages no post-H headers: the pause head must sit strictly past H"
            .to_string()
    })?;
    let end = antelope_slot_to_unix_micros(slot_at(last, 64, "last staged post-H header")?);
    if end < start {
        return Err(format!(
            "pause window ends ({end}) before it starts ({start}): refusing an unorderable window"
        ));
    }
    Ok((start, end))
}

/// Hydrate the portable portion of a full XPR chain-state-history snapshot.
///
/// Every row is decoded and validated before Arena is touched. The writes then
/// run inside an Arena undo session, so a duplicate or storage failure rolls
/// the target back to its prior state. The function deliberately rejects source
/// tables whose consensus representation has not yet been ported (permissions,
/// resource limits, protocol state, and generated transactions). Accepting
/// those tables while dropping their state would create a network that appears
/// bootable but is invalid at its first action.
///
/// This is therefore a safe, incremental boundary: it can import accounts
/// with deployed code and every contract-table/index row, while making the
/// remaining full-chain work explicit to the caller.
pub fn hydrate_full_state(
    db: &mut Database,
    entry: &StateHistoryEntry,
) -> Result<ImportSummary, XprImportError> {
    hydrate_full_state_with_deferred_transactions(db, entry, None)
}

/// Hydrate a full SHiP state export, verifying an optional direct-chainbase
/// deferred-transaction sidecar first.
///
/// The sidecar eliminates the data-loss boundary in SHiP and is validated
/// one-for-one against its `generated_transaction` rows. Verified records are
/// retained in Arena for the controller's deferred-transaction scheduler;
/// nothing is silently discarded at the migration boundary.
pub fn hydrate_full_state_with_deferred_transactions(
    db: &mut Database,
    entry: &StateHistoryEntry,
    deferred_transactions: Option<&DeferredTransactionSidecar>,
) -> Result<ImportSummary, XprImportError> {
    let rows = decode_portable_rows(entry)?;
    validate_code_links(&rows, entry.block_id, deferred_transactions)?;
    let mut summary = ImportSummary::default();

    db.arena_start_undo_session();
    let result = (|| {
        if let Some(sidecar) = deferred_transactions {
            for row in &sidecar.transactions {
                let key = sidecar_key(row)?;
                db.xpr_import_deferred_transaction(
                    key.sender,
                    key.sender_id,
                    key.payer,
                    key.trx_id,
                    row.delay_until,
                    row.expiration,
                    row.published,
                    &key.packed_trx,
                )
                .map_err(database_error)?;
                summary.deferred_transactions += 1;
            }
        }
        // The state-history table order happens to be suitable today, but the
        // importer enforces its own dependency order so an equivalent stream
        // with tables rearranged cannot create children before their parents.
        for row in &rows {
            if let PortableRow::GlobalProperty { config, .. } = row {
                db.set_global_properties(config).map_err(database_error)?;
                summary.global_properties += 1;
            }
        }
        for row in &rows {
            if let PortableRow::ProtocolState { features } = row {
                db.xpr_import_protocol_features(features)
                    .map_err(database_error)?;
                summary.source_activated_protocol_features = features.len() as u64;
            }
        }
        for row in &rows {
            if let PortableRow::Account {
                name,
                creation_date,
                abi,
            } = row
            {
                db.create_account(*name, *creation_date)
                    .map_err(database_error)?;
                db.xpr_import_set_account_abi_raw(*name, abi)
                    .map_err(database_error)?;
                summary.accounts += 1;
            }
        }
        for row in &rows {
            if let PortableRow::AccountMetadata {
                name,
                privileged,
                last_code_update,
                code,
            } = row
            {
                let (code_hash, vm_type, vm_version) = code
                    .as_ref()
                    .map(|reference| (reference.hash, reference.vm_type, reference.vm_version))
                    .unwrap_or(([0; 32], 0, 0));
                db.xpr_import_account_metadata(
                    *name,
                    *privileged,
                    *last_code_update,
                    code_hash,
                    vm_type,
                    vm_version,
                )
                .map_err(database_error)?;
                summary.account_metadata += 1;
            }
        }
        for row in &rows {
            if let PortableRow::Code {
                hash,
                code,
                vm_type,
                vm_version,
            } = row
            {
                db.xpr_import_code(
                    *hash,
                    code,
                    code_reference_count(&rows, *hash, *vm_type, *vm_version),
                    *vm_type,
                    *vm_version,
                )
                .map_err(database_error)?;
                summary.code_rows += 1;
            }
        }
        let mut permission_ids = HashMap::new();
        for row in &rows {
            if let PortableRow::Permission {
                owner,
                name,
                parent_name,
                last_updated,
                authority,
            } = row
            {
                let parent = if *parent_name == 0 {
                    0
                } else {
                    *permission_ids.get(&(*owner, *parent_name)).ok_or_else(|| {
                        bad(format!(
                            "permission {name} is ordered before its parent {parent_name}"
                        ))
                    })?
                };
                let id = db
                    .xpr_import_permission(parent, *owner, *name, *last_updated, authority)
                    .map_err(database_error)?;
                permission_ids.insert((*owner, *name), id);
                summary.permissions += 1;
            }
        }
        for row in &rows {
            if let PortableRow::PermissionLink {
                account,
                code,
                message_type,
                required_permission,
            } = row
            {
                db.xpr_import_permission_link(*account, *code, *message_type, *required_permission)
                    .map_err(database_error)?;
                summary.permission_links += 1;
            }
        }
        for row in &rows {
            if let PortableRow::ResourceLimits {
                owner,
                net_weight,
                cpu_weight,
                ram_bytes,
            } = row
            {
                db.xpr_import_resource_limits(*owner, *net_weight, *cpu_weight, *ram_bytes)
                    .map_err(database_error)?;
                summary.resource_limits += 1;
            }
            if let PortableRow::ResourceUsage {
                owner,
                ram_usage,
                net_usage,
                cpu_usage,
            } = row
            {
                db.xpr_import_resource_usage(
                    *owner,
                    *ram_usage,
                    net_usage.value_ex,
                    net_usage.consumed,
                    net_usage.last_ordinal,
                    cpu_usage.value_ex,
                    cpu_usage.consumed,
                    cpu_usage.last_ordinal,
                )
                .map_err(database_error)?;
                summary.resource_usage += 1;
            }
        }
        for row in &rows {
            if let PortableRow::ResourceState {
                net,
                cpu,
                total_net_weight,
                total_cpu_weight,
                total_ram_bytes,
                virtual_net_limit,
                virtual_cpu_limit,
            } = row
            {
                db.xpr_import_resource_state(
                    (net.value_ex, net.consumed, net.last_ordinal),
                    (cpu.value_ex, cpu.consumed, cpu.last_ordinal),
                    *total_net_weight,
                    *total_cpu_weight,
                    *total_ram_bytes,
                    *virtual_net_limit,
                    *virtual_cpu_limit,
                )
                .map_err(database_error)?;
                summary.resource_states += 1;
            }
            if let PortableRow::ResourceConfig {
                cpu,
                net,
                cpu_window,
                net_window,
            } = row
            {
                db.xpr_import_resource_config(*cpu, *net, *cpu_window, *net_window)
                    .map_err(database_error)?;
                summary.resource_configs += 1;
            }
        }
        // SHiP omits several chainbase bookkeeping fields. Apply the verified
        // source-node sidecar after the base rows exist, still inside the same
        // undo session so a missing or malformed row cannot partially commit.
        if let Some(sidecar) = deferred_transactions {
            db.xpr_import_global_action_sequence(sidecar.global_action_sequence)
                .map_err(database_error)?;
            let input_transactions = decode_input_transactions(sidecar)?;
            db.xpr_import_input_transactions(&input_transactions)
                .map_err(database_error)?;
            summary.input_transactions = input_transactions.len() as u64;
            for row in &sidecar.account_metadata {
                db.xpr_import_update_account_metadata(
                    row.name,
                    row.recv_sequence,
                    row.auth_sequence,
                    row.code_sequence,
                    row.abi_sequence,
                )
                .map_err(database_error)?;
            }
            for row in &sidecar.code {
                let code_hash = decode_block_id(&row.code_hash)?;
                db.xpr_import_update_code_metadata(
                    code_hash,
                    row.vm_type,
                    row.vm_version,
                    row.code_ref_count,
                    row.first_block_used,
                )
                .map_err(database_error)?;
            }
            for row in &sidecar.permissions {
                db.xpr_import_permission_last_used(row.owner, row.name, row.last_used)
                    .map_err(database_error)?;
            }
        }
        for row in rows {
            match row {
                PortableRow::Account { .. }
                | PortableRow::GlobalProperty { .. }
                | PortableRow::PermissionLink { .. }
                | PortableRow::ResourceLimits { .. }
                | PortableRow::ResourceUsage { .. }
                | PortableRow::ResourceState { .. }
                | PortableRow::ResourceConfig { .. }
                | PortableRow::AccountMetadata { .. }
                | PortableRow::Code { .. }
                | PortableRow::Permission { .. } => {}
                PortableRow::ProtocolState { .. } => {}
                PortableRow::GeneratedTransaction { .. } => {}
                PortableRow::ContractTable {
                    code,
                    scope,
                    table,
                    payer,
                } => {
                    db.xpr_import_create_contract_table(code, scope, table, payer)
                        .map_err(database_error)?;
                    summary.contract_tables += 1;
                }
                PortableRow::ContractRow {
                    code,
                    scope,
                    table,
                    primary,
                    payer,
                    value,
                } => {
                    db.create_key_value_object_standalone(
                        code, scope, table, payer, primary, &value,
                    )
                    .map_err(database_error)?;
                    summary.contract_rows += 1;
                }
                PortableRow::Index64 {
                    code,
                    scope,
                    table,
                    primary,
                    payer,
                    secondary,
                } => {
                    db.create_index64_object_standalone(
                        code, scope, table, payer, primary, secondary,
                    )
                    .map_err(database_error)?;
                    summary.index64_rows += 1;
                }
                PortableRow::Index128 {
                    code,
                    scope,
                    table,
                    primary,
                    payer,
                    secondary,
                } => {
                    db.create_index128_object_standalone(
                        code, scope, table, payer, primary, secondary,
                    )
                    .map_err(database_error)?;
                    summary.index128_rows += 1;
                }
                PortableRow::Index256 {
                    code,
                    scope,
                    table,
                    primary,
                    payer,
                    secondary,
                } => {
                    db.create_index256_object_standalone(
                        code, scope, table, payer, primary, secondary,
                    )
                    .map_err(database_error)?;
                    summary.index256_rows += 1;
                }
                PortableRow::IndexDouble {
                    code,
                    scope,
                    table,
                    primary,
                    payer,
                    secondary,
                } => {
                    db.create_idx_double_object_standalone(
                        code, scope, table, payer, primary, secondary,
                    )
                    .map_err(database_error)?;
                    summary.index_double_rows += 1;
                }
                PortableRow::IndexLongDouble {
                    code,
                    scope,
                    table,
                    primary,
                    payer,
                    secondary,
                } => {
                    db.create_idx_long_double_object_standalone(
                        code, scope, table, payer, primary, secondary,
                    )
                    .map_err(database_error)?;
                    summary.index_long_double_rows += 1;
                }
            }
        }
        Ok(())
    })();

    match result {
        Ok(()) => {
            db.arena_squash();
            Ok(summary)
        }
        Err(error) => {
            db.arena_undo();
            Err(error)
        }
    }
}

/// Apply one post-snapshot SHiP table-delta entry transactionally. The source
/// log's `present=false` rows are removals; modified rows are upserted using
/// their primary keys. Generated transactions are rejected until a matching
/// per-block chainbase sidecar is supplied, because SHiP v0 omits their timing.
pub fn apply_state_history_delta(
    db: &mut Database,
    entry: &StateHistoryEntry,
) -> Result<ImportSummary, XprImportError> {
    apply_state_history_delta_with_sidecar(db, entry, None)
}

/// Apply one post-snapshot SHiP table-delta entry with its optional source
/// chainbase sidecar. The sidecar is matched against the exact block and
/// generated-transaction rows before Arena is mutated.
pub fn apply_state_history_delta_with_sidecar(
    db: &mut Database,
    entry: &StateHistoryEntry,
    deferred_transactions: Option<&DeferredTransactionSidecar>,
) -> Result<ImportSummary, XprImportError> {
    let mut decoded = Vec::new();
    for delta in &entry.deltas {
        for row in &delta.rows {
            decoded.push((row.present, decode_portable_row(&delta.name, &row.data)?));
        }
    }
    validate_delta_sidecar(&decoded, entry.block_id, deferred_transactions)?;
    let delta_metadata_names: HashSet<u64> = decoded
        .iter()
        .filter_map(|(present, row)| match (present, row) {
            (true, PortableRow::AccountMetadata { name, .. }) => Some(*name),
            _ => None,
        })
        .collect();
    let delta_code_keys: HashSet<([u8; 32], u8, u8)> = decoded
        .iter()
        .filter_map(|(present, row)| match (present, row) {
            (
                true,
                PortableRow::Code {
                    hash,
                    vm_type,
                    vm_version,
                    ..
                },
            ) => Some((*hash, *vm_type, *vm_version)),
            _ => None,
        })
        .collect();
    let delta_permission_keys: HashSet<(u64, u64)> = decoded
        .iter()
        .filter_map(|(present, row)| match (present, row) {
            (true, PortableRow::Permission { owner, name, .. }) => Some((*owner, *name)),
            _ => None,
        })
        .collect();

    db.arena_start_undo_session();
    let mut summary = ImportSummary::default();
    let result = (|| {
        for (present, row) in decoded {
            if let PortableRow::GeneratedTransaction {
                sender,
                sender_id,
                payer,
                trx_id,
                packed_trx,
            } = row
            {
                if present {
                    let sidecar = deferred_transactions.ok_or_else(|| {
                        bad(format!(
                            "cannot apply block {}: generated_transaction rows require a per-block deferred sidecar",
                            hex::encode(entry.block_id)
                        ))
                    })?;
                    let sidecar_row = sidecar
                        .transactions
                        .iter()
                        .find(|candidate| {
                            candidate
                                .trx_id
                                .as_bytes()
                                .eq_ignore_ascii_case(hex::encode(trx_id).as_bytes())
                        })
                        .ok_or_else(|| {
                            bad(format!(
                                "deferred sidecar is missing generated transaction {}",
                                hex::encode(trx_id)
                            ))
                        })?;
                    let key = sidecar_key(sidecar_row)?;
                    if key.sender != sender
                        || key.sender_id != sender_id
                        || key.payer != payer
                        || key.trx_id != trx_id
                        || key.packed_trx != packed_trx
                    {
                        return Err(bad(format!(
                            "deferred sidecar identity mismatch for generated transaction {}",
                            hex::encode(trx_id)
                        )));
                    }
                    db.xpr_import_deferred_transaction(
                        sender,
                        sender_id,
                        payer,
                        trx_id,
                        sidecar_row.delay_until,
                        sidecar_row.expiration,
                        sidecar_row.published,
                        &packed_trx,
                    )
                    .map_err(database_error)?;
                    summary.deferred_transactions += 1;
                } else if !db
                    .arena_remove_deferred_transaction(trx_id)
                    .map_err(database_error)?
                {
                    return Err(bad(format!(
                        "generated transaction {} was removed by SHiP but is absent in Arena",
                        hex::encode(trx_id)
                    )));
                }
                continue;
            }
            apply_delta_row(db, present, row, &mut summary)?;
        }
        if let Some(sidecar) = deferred_transactions {
            db.xpr_import_global_action_sequence(sidecar.global_action_sequence)
                .map_err(database_error)?;
            let input_transactions = decode_input_transactions(sidecar)?;
            db.xpr_import_input_transactions(&input_transactions)
                .map_err(database_error)?;
            summary.input_transactions = input_transactions.len() as u64;
            for row in &sidecar.account_metadata {
                if !delta_metadata_names.contains(&row.name) {
                    continue;
                }
                db.xpr_import_update_account_metadata(
                    row.name,
                    row.recv_sequence,
                    row.auth_sequence,
                    row.code_sequence,
                    row.abi_sequence,
                )
                .map_err(database_error)?;
            }
            for row in &sidecar.code {
                let code_hash = decode_block_id(&row.code_hash)?;
                if !delta_code_keys.contains(&(code_hash, row.vm_type, row.vm_version)) {
                    continue;
                }
                db.xpr_import_update_code_metadata(
                    code_hash,
                    row.vm_type,
                    row.vm_version,
                    row.code_ref_count,
                    row.first_block_used,
                )
                .map_err(database_error)?;
            }
            for row in &sidecar.permissions {
                if !delta_permission_keys.contains(&(row.owner, row.name)) {
                    continue;
                }
                db.xpr_import_permission_last_used(row.owner, row.name, row.last_used)
                    .map_err(database_error)?;
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            db.arena_squash();
            Ok(summary)
        }
        Err(error) => {
            db.arena_undo();
            Err(error)
        }
    }
}

/// Stream and apply up to `max_post_snapshot_entries` after the initial full
/// state record. The first record is framed and skipped; each later record is
/// committed independently so a bad block rolls back only its own changes.
pub fn apply_state_history_log_window(
    db: &mut Database,
    path: impl AsRef<Path>,
    max_post_snapshot_entries: u64,
) -> Result<u64, XprImportError> {
    apply_state_history_log_window_inner(db, path.as_ref(), None, max_post_snapshot_entries)
}

/// Stream and apply a bounded history window, loading optional per-block
/// sidecars from `<sidecar_dir>/<block-id>.json`. Missing files are allowed
/// for blocks without generated transactions; a block that contains one still
/// fails closed through [`apply_state_history_delta_with_sidecar`].
pub fn apply_state_history_log_window_with_sidecars(
    db: &mut Database,
    path: impl AsRef<Path>,
    sidecar_dir: impl AsRef<Path>,
    max_post_snapshot_entries: u64,
) -> Result<u64, XprImportError> {
    apply_state_history_log_window_inner(
        db,
        path.as_ref(),
        Some(sidecar_dir.as_ref()),
        max_post_snapshot_entries,
    )
}

fn apply_state_history_log_window_inner(
    db: &mut Database,
    path: &Path,
    sidecar_dir: Option<&Path>,
    max_post_snapshot_entries: u64,
) -> Result<u64, XprImportError> {
    let mut file =
        File::open(path).map_err(|error| bad(format!("opening state-history log: {error}")))?;
    let mut offset = 0u64;
    let mut previous_block_num: Option<u32> = None;
    let mut entry_number = 0u64;
    let mut applied = 0u64;
    loop {
        let mut header = [0u8; LOG_HEADER_LEN];
        match file.read(&mut header[..1]) {
            Ok(0) => break,
            Ok(1) => {}
            Ok(_) => unreachable!(),
            Err(error) => return Err(bad(format!("reading state-history header: {error}"))),
        }
        file.read_exact(&mut header[1..])
            .map_err(|error| bad(format!("truncated state-history header: {error}")))?;
        let magic = u64::from_le_bytes(header[0..8].try_into().unwrap());
        if (magic as u16) != 0 {
            return Err(bad(format!(
                "unsupported XPR state-history version {}",
                magic as u16
            )));
        }
        let mut block_id = [0u8; 32];
        block_id.copy_from_slice(&header[8..40]);
        let payload_len = u64::from_le_bytes(header[40..48].try_into().unwrap());
        let next_offset = offset
            .checked_add(LOG_HEADER_LEN as u64)
            .and_then(|n| n.checked_add(payload_len))
            .and_then(|n| n.checked_add(LOG_TRAILER_LEN as u64))
            .ok_or_else(|| bad("state-history record offset overflows"))?;
        let block_num = u32::from_be_bytes(block_id[..4].try_into().unwrap());
        if let Some(previous) = previous_block_num
            && block_num != previous.saturating_add(1)
        {
            return Err(bad(format!(
                "state-history block sequence jumps from {previous} to {block_num}"
            )));
        }
        previous_block_num = Some(block_num);

        if entry_number == 0 {
            file.seek(SeekFrom::Current(i64::try_from(payload_len).map_err(
                |_| bad("state-history payload offset does not fit i64"),
            )?))
            .map_err(|error| bad(format!("skipping initial state payload: {error}")))?;
        } else {
            if applied >= max_post_snapshot_entries {
                break;
            }
            let payload_len = usize::try_from(payload_len)
                .map_err(|_| bad("state-history payload length does not fit this platform"))?;
            let mut payload = vec![0u8; payload_len];
            file.read_exact(&mut payload)
                .map_err(|error| bad(format!("reading state-history payload: {error}")))?;
            let entry = StateHistoryEntry {
                magic,
                block_id,
                deltas: parse_table_deltas(&decompress_state_history_payload(&payload)?)?,
            };
            let sidecar = match sidecar_dir {
                Some(directory) => {
                    let sidecar_path = directory.join(format!("{}.json", hex::encode(block_id)));
                    match fs::read(&sidecar_path) {
                        Ok(bytes) => Some(DeferredTransactionSidecar::from_json_bytes(&bytes)?),
                        Err(error) if error.kind() == ErrorKind::NotFound => None,
                        Err(error) => {
                            return Err(bad(format!(
                                "reading deferred sidecar {}: {error}",
                                sidecar_path.display()
                            )));
                        }
                    }
                }
                None => None,
            };
            apply_state_history_delta_with_sidecar(db, &entry, sidecar.as_ref())?;
            applied += 1;
        }

        let mut trailer = [0u8; LOG_TRAILER_LEN];
        file.read_exact(&mut trailer)
            .map_err(|error| bad(format!("truncated state-history record trailer: {error}")))?;
        let recorded_offset = u64::from_le_bytes(trailer);
        if recorded_offset != offset {
            return Err(bad(format!(
                "state-history record at offset {offset} carries trailer offset {recorded_offset}"
            )));
        }
        offset = next_offset;
        entry_number += 1;
        if entry_number > 1 && applied >= max_post_snapshot_entries {
            break;
        }
    }
    Ok(applied)
}

fn apply_delta_row(
    db: &mut Database,
    present: bool,
    row: PortableRow,
    summary: &mut ImportSummary,
) -> Result<(), XprImportError> {
    let missing = |table: &str| bad(format!("cannot remove unsupported singleton row {table}"));
    match row {
        PortableRow::GlobalProperty { config, .. } if present => {
            db.set_global_properties(&config).map_err(database_error)?;
            summary.global_properties += 1;
        }
        PortableRow::GlobalProperty { .. } => return Err(missing("global_property")),
        PortableRow::ProtocolState { features } if present => {
            db.xpr_import_protocol_features(&features)
                .map_err(database_error)?;
            summary.source_activated_protocol_features = features.len() as u64;
        }
        PortableRow::ProtocolState { .. } => return Err(missing("protocol_state")),
        PortableRow::Account {
            name,
            creation_date,
            abi,
        } if present => {
            if db.is_account(name).map_err(database_error)? {
                db.xpr_import_set_account_abi_raw(name, &abi)
                    .map_err(database_error)?;
            } else {
                db.create_account(name, creation_date)
                    .map_err(database_error)?;
                db.xpr_import_set_account_abi_raw(name, &abi)
                    .map_err(database_error)?;
            }
            summary.accounts += 1;
        }
        PortableRow::Account { .. } => {
            return Err(bad(
                "account removals are not supported by the Arena importer",
            ));
        }
        PortableRow::AccountMetadata {
            name,
            privileged,
            last_code_update,
            code,
        } if present => {
            let (hash, vm_type, vm_version) = code
                .map(|reference| (reference.hash, reference.vm_type, reference.vm_version))
                .unwrap_or(([0; 32], 0, 0));
            if db.arena_account_metadata(name).is_some() {
                db.xpr_import_update_account_metadata_source(
                    name,
                    privileged,
                    last_code_update,
                    hash,
                    vm_type,
                    vm_version,
                )
                .map_err(database_error)?;
            } else {
                db.xpr_import_account_metadata(
                    name,
                    privileged,
                    last_code_update,
                    hash,
                    vm_type,
                    vm_version,
                )
                .map_err(database_error)?;
            }
            summary.account_metadata += 1;
        }
        PortableRow::AccountMetadata { .. } => {
            return Err(bad(
                "account_metadata removals are not supported by the Arena importer",
            ));
        }
        PortableRow::Code {
            hash,
            code,
            vm_type,
            vm_version,
        } if present => {
            if db
                .get_code_bytes_by_hash(&hash, vm_type, vm_version)
                .is_ok()
            {
                db.xpr_import_update_code(hash, &code, vm_type, vm_version)
                    .map_err(database_error)?;
            } else {
                db.xpr_import_code(hash, &code, 0, vm_type, vm_version)
                    .map_err(database_error)?;
            }
            summary.code_rows += 1;
        }
        PortableRow::Code {
            hash,
            vm_type,
            vm_version,
            ..
        } => {
            if !db
                .xpr_import_remove_code(hash, vm_type, vm_version)
                .map_err(database_error)?
            {
                return Err(bad(format!(
                    "code removal {} is absent from Arena",
                    hex::encode(hash)
                )));
            }
            summary.code_rows += 1;
        }
        PortableRow::Permission {
            owner,
            name,
            parent_name,
            last_updated,
            authority,
        } if present => {
            db.xpr_import_upsert_permission(parent_name, owner, name, last_updated, &authority)
                .map_err(database_error)?;
            summary.permissions += 1;
        }
        PortableRow::Permission { owner, name, .. } => {
            db.xpr_import_remove_permission(owner, name)
                .map_err(database_error)?;
        }
        PortableRow::PermissionLink {
            account,
            code,
            message_type,
            required_permission,
        } if present => {
            db.xpr_import_permission_link(account, code, message_type, required_permission)
                .map_err(database_error)?;
            summary.permission_links += 1;
        }
        PortableRow::PermissionLink {
            account,
            code,
            message_type,
            ..
        } => {
            db.unlink_auth(account, code, message_type)
                .map_err(database_error)?;
        }
        PortableRow::ResourceLimits {
            owner,
            net_weight,
            cpu_weight,
            ram_bytes,
        } if present => {
            db.xpr_import_resource_limits(owner, net_weight, cpu_weight, ram_bytes)
                .map_err(database_error)?;
            summary.resource_limits += 1;
        }
        PortableRow::ResourceLimits { .. } => {
            return Err(bad(
                "resource_limits removals are not supported by the Arena importer",
            ));
        }
        PortableRow::ResourceUsage {
            owner,
            ram_usage,
            net_usage,
            cpu_usage,
        } if present => {
            db.xpr_import_resource_usage(
                owner,
                ram_usage,
                net_usage.value_ex,
                net_usage.consumed,
                net_usage.last_ordinal,
                cpu_usage.value_ex,
                cpu_usage.consumed,
                cpu_usage.last_ordinal,
            )
            .map_err(database_error)?;
            summary.resource_usage += 1;
        }
        PortableRow::ResourceUsage { .. } => {
            return Err(bad(
                "resource_usage removals are not supported by the Arena importer",
            ));
        }
        PortableRow::ResourceState {
            net,
            cpu,
            total_net_weight,
            total_cpu_weight,
            total_ram_bytes,
            virtual_net_limit,
            virtual_cpu_limit,
        } if present => {
            db.xpr_import_resource_state(
                (net.value_ex, net.consumed, net.last_ordinal),
                (cpu.value_ex, cpu.consumed, cpu.last_ordinal),
                total_net_weight,
                total_cpu_weight,
                total_ram_bytes,
                virtual_net_limit,
                virtual_cpu_limit,
            )
            .map_err(database_error)?;
            summary.resource_states += 1;
        }
        PortableRow::ResourceState { .. } => return Err(missing("resource_limits_state")),
        PortableRow::ResourceConfig {
            cpu,
            net,
            cpu_window,
            net_window,
        } if present => {
            db.xpr_import_resource_config(cpu, net, cpu_window, net_window)
                .map_err(database_error)?;
            summary.resource_configs += 1;
        }
        PortableRow::ResourceConfig { .. } => return Err(missing("resource_limits_config")),
        PortableRow::ContractTable {
            code,
            scope,
            table,
            payer,
        } if present => {
            db.xpr_import_create_contract_table(code, scope, table, payer)
                .map_err(database_error)?;
            summary.contract_tables += 1;
        }
        PortableRow::ContractTable {
            code, scope, table, ..
        } => {
            db.xpr_import_remove_contract_table(code, scope, table)
                .map_err(database_error)?;
        }
        PortableRow::ContractRow {
            code,
            scope,
            table,
            primary,
            payer,
            value,
        } if present => {
            if db.arena_kv_row(code, scope, table, primary).is_some() {
                db.update_key_value_object_standalone(code, scope, table, primary, payer, &value)
                    .map_err(database_error)?;
            } else {
                db.create_key_value_object_standalone(code, scope, table, payer, primary, &value)
                    .map_err(database_error)?;
            }
            summary.contract_rows += 1;
        }
        PortableRow::ContractRow {
            code,
            scope,
            table,
            primary,
            ..
        } => {
            db.remove_key_value_object_standalone(code, scope, table, primary)
                .map_err(database_error)?;
        }
        PortableRow::Index64 {
            code,
            scope,
            table,
            primary,
            payer,
            secondary,
        } => apply_index64(
            db, present, code, scope, table, primary, payer, secondary, summary,
        )?,
        PortableRow::Index128 {
            code,
            scope,
            table,
            primary,
            payer,
            secondary,
        } => apply_index128(
            db, present, code, scope, table, primary, payer, secondary, summary,
        )?,
        PortableRow::Index256 {
            code,
            scope,
            table,
            primary,
            payer,
            secondary,
        } => apply_index256(
            db, present, code, scope, table, primary, payer, secondary, summary,
        )?,
        PortableRow::IndexDouble {
            code,
            scope,
            table,
            primary,
            payer,
            secondary,
        } => apply_index_double(
            db, present, code, scope, table, primary, payer, secondary, summary,
        )?,
        PortableRow::IndexLongDouble {
            code,
            scope,
            table,
            primary,
            payer,
            secondary,
        } => apply_index_long_double(
            db, present, code, scope, table, primary, payer, secondary, summary,
        )?,
        PortableRow::GeneratedTransaction { .. } => unreachable!(),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_index64(
    db: &mut Database,
    present: bool,
    code: u64,
    scope: u64,
    table: u64,
    primary: u64,
    payer: u64,
    secondary: u64,
    summary: &mut ImportSummary,
) -> Result<(), XprImportError> {
    if present {
        if db.arena_idx64_payer(code, scope, table, primary).is_some() {
            db.update_index64_object_standalone(code, scope, table, primary, payer, secondary)
        } else {
            db.create_index64_object_standalone(code, scope, table, payer, primary, secondary)
        }
        .map_err(database_error)?;
        summary.index64_rows += 1;
    } else {
        db.remove_index64_object_standalone(code, scope, table, primary)
            .map_err(database_error)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_index128(
    db: &mut Database,
    present: bool,
    code: u64,
    scope: u64,
    table: u64,
    primary: u64,
    payer: u64,
    secondary: u128,
    summary: &mut ImportSummary,
) -> Result<(), XprImportError> {
    if present {
        if db.arena_idx128_payer(code, scope, table, primary).is_some() {
            db.update_index128_object_standalone(code, scope, table, primary, payer, secondary)
        } else {
            db.create_index128_object_standalone(code, scope, table, payer, primary, secondary)
        }
        .map_err(database_error)?;
        summary.index128_rows += 1;
    } else {
        db.remove_index128_object_standalone(code, scope, table, primary)
            .map_err(database_error)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_index256(
    db: &mut Database,
    present: bool,
    code: u64,
    scope: u64,
    table: u64,
    primary: u64,
    payer: u64,
    secondary: U256,
    summary: &mut ImportSummary,
) -> Result<(), XprImportError> {
    if present {
        if db.arena_idx256_payer(code, scope, table, primary).is_some() {
            db.update_index256_object_standalone(code, scope, table, primary, payer, secondary)
        } else {
            db.create_index256_object_standalone(code, scope, table, payer, primary, secondary)
        }
        .map_err(database_error)?;
        summary.index256_rows += 1;
    } else {
        db.remove_index256_object_standalone(code, scope, table, primary)
            .map_err(database_error)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_index_double(
    db: &mut Database,
    present: bool,
    code: u64,
    scope: u64,
    table: u64,
    primary: u64,
    payer: u64,
    secondary: u64,
    summary: &mut ImportSummary,
) -> Result<(), XprImportError> {
    if present {
        if db
            .arena_idx_double_payer(code, scope, table, primary)
            .is_some()
        {
            db.update_idx_double_object_standalone(code, scope, table, primary, payer, secondary)
        } else {
            db.create_idx_double_object_standalone(code, scope, table, payer, primary, secondary)
        }
        .map_err(database_error)?;
        summary.index_double_rows += 1;
    } else {
        db.remove_idx_double_object_standalone(code, scope, table, primary)
            .map_err(database_error)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_index_long_double(
    db: &mut Database,
    present: bool,
    code: u64,
    scope: u64,
    table: u64,
    primary: u64,
    payer: u64,
    secondary: Float128,
    summary: &mut ImportSummary,
) -> Result<(), XprImportError> {
    if present {
        if db
            .arena_idx_long_double_payer(code, scope, table, primary)
            .is_some()
        {
            db.update_idx_long_double_object_standalone(
                code, scope, table, primary, payer, secondary,
            )
        } else {
            db.create_idx_long_double_object_standalone(
                code, scope, table, payer, primary, secondary,
            )
        }
        .map_err(database_error)?;
        summary.index_long_double_rows += 1;
    } else {
        db.remove_idx_long_double_object_standalone(code, scope, table, primary)
            .map_err(database_error)?;
    }
    Ok(())
}

fn database_error(error: impl fmt::Display) -> XprImportError {
    bad(format!("writing Arena state: {error}"))
}

enum PortableRow {
    /// XPR's producer schedule is deliberately not carried over: the imported
    /// database starts a new Pulse chain with its own producer schedule. Its
    /// chain execution configuration is retained in Arena.
    GlobalProperty {
        config: ChainConfigV0,
        source_chain_id: [u8; 32],
    },
    /// Source activation history is retained for lossless state-history export,
    /// but not replayed into the independent Pulse runtime.
    ProtocolState { features: Vec<([u8; 32], u32)> },
    PermissionLink {
        account: u64,
        code: u64,
        message_type: u64,
        required_permission: u64,
    },
    ResourceLimits {
        owner: u64,
        net_weight: i64,
        cpu_weight: i64,
        ram_bytes: i64,
    },
    ResourceUsage {
        owner: u64,
        ram_usage: u64,
        net_usage: ImportUsage,
        cpu_usage: ImportUsage,
    },
    ResourceState {
        net: ImportUsage,
        cpu: ImportUsage,
        total_net_weight: u64,
        total_cpu_weight: u64,
        total_ram_bytes: u64,
        virtual_net_limit: u64,
        virtual_cpu_limit: u64,
    },
    ResourceConfig {
        cpu: crate::backend::ElasticParams,
        net: crate::backend::ElasticParams,
        cpu_window: u32,
        net_window: u32,
    },
    Account {
        name: u64,
        creation_date: u32,
        abi: Vec<u8>,
    },
    AccountMetadata {
        name: u64,
        privileged: bool,
        last_code_update: i64,
        code: Option<CodeReference>,
    },
    Code {
        hash: [u8; 32],
        code: Vec<u8>,
        vm_type: u8,
        vm_version: u8,
    },
    /// The SHiP v0 projection of a chainbase generated transaction. This is
    /// deliberately not hydrated yet: SHiP omits the chainbase scheduling
    /// timestamps required to execute it safely after migration.
    GeneratedTransaction {
        sender: u64,
        sender_id: u128,
        payer: u64,
        trx_id: [u8; 32],
        packed_trx: Vec<u8>,
    },
    Permission {
        owner: u64,
        name: u64,
        parent_name: u64,
        last_updated: i64,
        authority: Vec<u8>,
    },
    ContractTable {
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
    },
    ContractRow {
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        payer: u64,
        value: Vec<u8>,
    },
    Index64 {
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        payer: u64,
        secondary: u64,
    },
    Index128 {
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        payer: u64,
        secondary: u128,
    },
    Index256 {
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        payer: u64,
        secondary: U256,
    },
    IndexDouble {
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        payer: u64,
        secondary: u64,
    },
    IndexLongDouble {
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        payer: u64,
        secondary: Float128,
    },
}

#[derive(Clone, Copy)]
struct CodeReference {
    hash: [u8; 32],
    vm_type: u8,
    vm_version: u8,
}

#[derive(Clone, Copy)]
struct ImportUsage {
    value_ex: u64,
    consumed: u64,
    last_ordinal: u32,
}

fn decode_portable_rows(entry: &StateHistoryEntry) -> Result<Vec<PortableRow>, XprImportError> {
    let mut result = Vec::new();
    for delta in &entry.deltas {
        for row in &delta.rows {
            if !row.present {
                return Err(bad(format!(
                    "table {:?} contains a removal; expected a full-state export",
                    delta.name
                )));
            }
            result.push(decode_portable_row(&delta.name, &row.data)?);
        }
    }
    Ok(result)
}

fn decode_portable_row(name: &str, data: &[u8]) -> Result<PortableRow, XprImportError> {
    match name {
        "global_property" => decode_global_property(data),
        "protocol_state" => decode_protocol_state(data),
        "permission_link" => decode_permission_link(data),
        "resource_limits" => decode_resource_limits(data),
        "resource_usage" => decode_resource_usage(data),
        "resource_limits_state" => decode_resource_state(data),
        "resource_limits_config" => decode_resource_config(data),
        "account" => decode_account(data),
        "account_metadata" => decode_account_metadata(data),
        "code" => decode_code(data),
        "generated_transaction" => decode_generated_transaction(data),
        "permission" => decode_permission(data),
        "contract_table" => decode_contract_table(data),
        "contract_row" => decode_contract_row(data),
        "contract_index64" => decode_index64(data),
        "contract_index128" => decode_index128(data),
        "contract_index256" => decode_index256(data),
        "contract_index_double" => decode_index_double(data),
        "contract_index_long_double" => decode_index_long_double(data),
        table => Err(bad(format!(
            "XPR table {table:?} is not supported by the importer yet"
        ))),
    }
}

fn validate_code_links(
    rows: &[PortableRow],
    source_block_id: [u8; 32],
    deferred_transactions: Option<&DeferredTransactionSidecar>,
) -> Result<(), XprImportError> {
    validate_deferred_transactions(rows, source_block_id, deferred_transactions)?;
    validate_sidecar_fields(rows, deferred_transactions)?;
    let mut code_keys = HashSet::new();
    for row in rows {
        if let PortableRow::Code {
            hash,
            vm_type,
            vm_version,
            ..
        } = row
            && !code_keys.insert((*hash, *vm_type, *vm_version))
        {
            return Err(bad("duplicate XPR code row"));
        }
    }
    for row in rows {
        if let PortableRow::AccountMetadata {
            name,
            code: Some(code),
            ..
        } = row
            && !code_keys.contains(&(code.hash, code.vm_type, code.vm_version))
        {
            return Err(bad(format!(
                "account metadata for {name} references code absent from the full-state export"
            )));
        }
    }
    Ok(())
}

fn validate_sidecar_fields(
    rows: &[PortableRow],
    sidecar: Option<&DeferredTransactionSidecar>,
) -> Result<(), XprImportError> {
    let Some(sidecar) = sidecar else {
        return Ok(());
    };

    if let Some(source_chain_id) = &sidecar.source_chain_id {
        let expected = decode_block_id(source_chain_id)
            .map_err(|error| bad(format!("invalid source chain id: {error}")))?;
        let mut seen = false;
        for row in rows {
            if let PortableRow::GlobalProperty {
                source_chain_id, ..
            } = row
            {
                seen = true;
                if *source_chain_id != expected {
                    return Err(bad(
                        "sidecar source chain id does not match global_property",
                    ));
                }
            }
        }
        if !seen {
            return Err(bad(
                "sidecar source chain id supplied but full-state export has no global_property",
            ));
        }
    }

    let require_complete_tables = sidecar.source_chain_id.is_some();
    if require_complete_tables || !sidecar.account_metadata.is_empty() {
        let expected: HashSet<u64> = rows
            .iter()
            .filter_map(|row| match row {
                PortableRow::AccountMetadata { name, .. } => Some(*name),
                _ => None,
            })
            .collect();
        let actual: HashSet<u64> = sidecar
            .account_metadata
            .iter()
            .map(|row| row.name)
            .collect();
        if actual != expected {
            return Err(bad(
                "account_metadata sidecar does not exactly cover the SHiP rows",
            ));
        }
    }

    if require_complete_tables || !sidecar.code.is_empty() {
        let expected: HashSet<([u8; 32], u8, u8)> = rows
            .iter()
            .filter_map(|row| match row {
                PortableRow::Code {
                    hash,
                    vm_type,
                    vm_version,
                    ..
                } => Some((*hash, *vm_type, *vm_version)),
                _ => None,
            })
            .collect();
        let mut actual = HashSet::new();
        for row in &sidecar.code {
            let hash = decode_block_id(&row.code_hash)
                .map_err(|error| bad(format!("invalid code sidecar hash: {error}")))?;
            actual.insert((hash, row.vm_type, row.vm_version));
        }
        if actual != expected {
            return Err(bad("code sidecar does not exactly cover the SHiP rows"));
        }
    }

    if require_complete_tables || !sidecar.permissions.is_empty() {
        let expected: HashSet<(u64, u64)> = rows
            .iter()
            .filter_map(|row| match row {
                PortableRow::Permission { owner, name, .. } => Some((*owner, *name)),
                _ => None,
            })
            .collect();
        let actual: HashSet<(u64, u64)> = sidecar
            .permissions
            .iter()
            .map(|row| (row.owner, row.name))
            .collect();
        if actual != expected {
            return Err(bad(
                "permission sidecar does not exactly cover the SHiP rows",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DeferredTransactionKey {
    sender: u64,
    sender_id: u128,
    payer: u64,
    trx_id: [u8; 32],
    packed_trx: Vec<u8>,
}

fn validate_deferred_transactions(
    rows: &[PortableRow],
    source_block_id: [u8; 32],
    sidecar: Option<&DeferredTransactionSidecar>,
) -> Result<(), XprImportError> {
    let generated = rows
        .iter()
        .filter_map(|row| match row {
            PortableRow::GeneratedTransaction {
                sender,
                sender_id,
                payer,
                trx_id,
                packed_trx,
            } => Some(DeferredTransactionKey {
                sender: *sender,
                sender_id: *sender_id,
                payer: *payer,
                trx_id: *trx_id,
                packed_trx: packed_trx.clone(),
            }),
            _ => None,
        })
        .collect::<Vec<_>>();

    match (generated.is_empty(), sidecar) {
        (true, None) => return Ok(()),
        (true, Some(sidecar)) if sidecar.transactions.is_empty() => {
            validate_sidecar_block_id(sidecar, source_block_id)?;
            return Ok(());
        }
        (true, Some(_)) => {
            return Err(bad(
                "deferred-transaction sidecar contains rows but SHiP full-state export has none",
            ));
        }
        (false, None) => {
            let first = &generated[0];
            return Err(bad(format!(
                "generated_transaction {} (sender {}, sender_id {}, payer {}, packed bytes {}) cannot be imported from SHiP v0: its row omits delay_until, expiration, and published; use a chainbase-sidecar export before migrating deferred transactions",
                hex::encode(first.trx_id),
                first.sender,
                first.sender_id,
                first.payer,
                first.packed_trx.len()
            )));
        }
        (false, Some(sidecar)) => validate_sidecar_block_id(sidecar, source_block_id)?,
    }

    let mut expected = HashSet::new();
    let mut expected_transaction_ids = HashSet::new();
    for key in generated {
        if !expected.insert(key.clone()) || !expected_transaction_ids.insert(key.trx_id) {
            return Err(bad(
                "duplicate generated_transaction row in SHiP full-state export",
            ));
        }
    }
    let mut actual = HashSet::new();
    let mut actual_transaction_ids = HashSet::new();
    for row in &sidecar
        .expect("non-empty SHiP requires sidecar")
        .transactions
    {
        let key = sidecar_key(row)?;
        if !actual.insert(key.clone()) || !actual_transaction_ids.insert(key.trx_id) {
            return Err(bad(
                "duplicate generated_transaction row in chainbase sidecar",
            ));
        }
    }
    if expected != actual {
        return Err(bad(
            "deferred-transaction sidecar rows do not exactly match SHiP generated_transaction rows",
        ));
    }

    Ok(())
}

fn validate_sidecar_block_id(
    sidecar: &DeferredTransactionSidecar,
    source_block_id: [u8; 32],
) -> Result<(), XprImportError> {
    let block_id = decode_block_id(&sidecar.source_block_id)?;
    if block_id != source_block_id {
        return Err(bad(format!(
            "deferred-transaction sidecar block {} does not match SHiP full-state block {}",
            sidecar.source_block_id,
            hex::encode(source_block_id)
        )));
    }
    Ok(())
}

fn validate_delta_sidecar(
    rows: &[(bool, PortableRow)],
    source_block_id: [u8; 32],
    sidecar: Option<&DeferredTransactionSidecar>,
) -> Result<(), XprImportError> {
    let generated = rows
        .iter()
        .filter_map(|(present, row)| match (present, row) {
            (
                true,
                PortableRow::GeneratedTransaction {
                    sender,
                    sender_id,
                    payer,
                    trx_id,
                    packed_trx,
                },
            ) => Some(DeferredTransactionKey {
                sender: *sender,
                sender_id: *sender_id,
                payer: *payer,
                trx_id: *trx_id,
                packed_trx: packed_trx.clone(),
            }),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut generated_transaction_ids = HashSet::new();
    for key in &generated {
        if !generated_transaction_ids.insert(key.trx_id) {
            return Err(bad("duplicate generated_transaction row in SHiP delta"));
        }
    }
    let Some(sidecar) = sidecar else {
        if !generated.is_empty() {
            let first = generated.iter().next().expect("non-empty generated set");
            return Err(bad(format!(
                "cannot apply block {}: generated_transaction {} requires a per-block deferred sidecar",
                hex::encode(source_block_id),
                hex::encode(first.trx_id)
            )));
        }
        return Ok(());
    };

    validate_sidecar_block_id(sidecar, source_block_id)?;
    if let Some(source_chain_id) = &sidecar.source_chain_id {
        decode_block_id(source_chain_id)
            .map_err(|error| bad(format!("invalid source chain id: {error}")))?;
    }
    let mut actual = HashSet::new();
    let mut actual_transaction_ids = HashSet::new();
    for row in &sidecar.transactions {
        let key = sidecar_key(row)?;
        if !actual.insert(key.clone()) || !actual_transaction_ids.insert(key.trx_id) {
            return Err(bad(
                "duplicate generated_transaction row in chainbase delta sidecar",
            ));
        }
    }
    if !generated.is_subset(&actual) {
        return Err(bad(
            "deferred-transaction sidecar does not cover present SHiP generated_transaction rows",
        ));
    }

    let expected_metadata: HashSet<u64> = rows
        .iter()
        .filter_map(|(present, row)| match (present, row) {
            (true, PortableRow::AccountMetadata { name, .. }) => Some(*name),
            _ => None,
        })
        .collect();
    let actual_metadata: HashSet<u64> = sidecar
        .account_metadata
        .iter()
        .map(|row| row.name)
        .collect();
    if !expected_metadata.is_subset(&actual_metadata)
        || actual_metadata.len() != sidecar.account_metadata.len()
    {
        return Err(bad(
            "account_metadata sidecar does not cover the SHiP delta rows",
        ));
    }

    let expected_code: HashSet<([u8; 32], u8, u8)> = rows
        .iter()
        .filter_map(|(present, row)| match (present, row) {
            (
                true,
                PortableRow::Code {
                    hash,
                    vm_type,
                    vm_version,
                    ..
                },
            ) => Some((*hash, *vm_type, *vm_version)),
            _ => None,
        })
        .collect();
    let mut actual_code = HashSet::new();
    for row in &sidecar.code {
        let hash = decode_block_id(&row.code_hash)
            .map_err(|error| bad(format!("invalid code sidecar hash: {error}")))?;
        actual_code.insert((hash, row.vm_type, row.vm_version));
    }
    if !expected_code.is_subset(&actual_code) || actual_code.len() != sidecar.code.len() {
        return Err(bad("code sidecar does not cover the SHiP delta rows"));
    }

    let expected_permissions: HashSet<(u64, u64)> = rows
        .iter()
        .filter_map(|(present, row)| match (present, row) {
            (true, PortableRow::Permission { owner, name, .. }) => Some((*owner, *name)),
            _ => None,
        })
        .collect();
    let actual_permissions: HashSet<(u64, u64)> = sidecar
        .permissions
        .iter()
        .map(|row| (row.owner, row.name))
        .collect();
    if !expected_permissions.is_subset(&actual_permissions)
        || actual_permissions.len() != sidecar.permissions.len()
    {
        return Err(bad("permission sidecar does not cover the SHiP delta rows"));
    }
    Ok(())
}

fn decode_block_id(value: &str) -> Result<[u8; 32], XprImportError> {
    let bytes = hex::decode(value).map_err(|error| {
        bad(format!(
            "invalid deferred-transaction sidecar block id: {error}"
        ))
    })?;
    bytes.try_into().map_err(|_| {
        bad("invalid deferred-transaction sidecar block id: expected 32-byte hexadecimal value")
    })
}

fn decode_input_transactions(
    sidecar: &DeferredTransactionSidecar,
) -> Result<Vec<([u8; 32], u32)>, XprImportError> {
    sidecar
        .input_transactions
        .iter()
        .map(|row| {
            decode_block_id(&row.trx_id)
                .map(|trx_id| (trx_id, row.expiration))
                .map_err(|error| bad(format!("invalid input transaction id: {error}")))
        })
        .collect()
}

fn sidecar_key(
    row: &DeferredTransactionSidecarRow,
) -> Result<DeferredTransactionKey, XprImportError> {
    let sender_id = row.sender_id.parse::<u128>().map_err(|error| {
        bad(format!(
            "invalid deferred-transaction sidecar sender_id {:?}: {error}",
            row.sender_id
        ))
    })?;
    let trx_id = hex::decode(&row.trx_id)
        .map_err(|error| {
            bad(format!(
                "invalid deferred-transaction sidecar trx_id: {error}"
            ))
        })?
        .try_into()
        .map_err(|_| {
            bad("invalid deferred-transaction sidecar trx_id: expected 32-byte hexadecimal value")
        })?;
    let packed_trx = hex::decode(&row.packed_trx).map_err(|error| {
        bad(format!(
            "invalid deferred-transaction sidecar packed_trx: {error}"
        ))
    })?;
    Ok(DeferredTransactionKey {
        sender: row.sender,
        sender_id,
        payer: row.payer,
        trx_id,
        packed_trx,
    })
}

fn decode_generated_transaction(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    let sender = row.u64()?;
    let sender_id_lo = row.u64()?;
    let sender_id_hi = row.u64()?;
    let payer = row.u64()?;
    let trx_id = row.fixed::<32>()?;
    let packed_trx = row.bytes()?;
    row.finish()?;
    Ok(PortableRow::GeneratedTransaction {
        sender,
        sender_id: (sender_id_lo as u128) | ((sender_id_hi as u128) << 64),
        payer,
        trx_id,
        packed_trx,
    })
}

fn code_reference_count(rows: &[PortableRow], hash: [u8; 32], vm_type: u8, vm_version: u8) -> u64 {
    rows
        .iter()
        .filter(|row| {
            matches!(row, PortableRow::AccountMetadata { code: Some(reference), .. }
                if reference.hash == hash && reference.vm_type == vm_type && reference.vm_version == vm_version)
        })
        .count() as u64
}

fn decode_global_property(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    let version = row.varuint()?;
    if version != 1 {
        return Err(bad(format!(
            "unsupported XPR global_property version {version}"
        )));
    }

    // Leap 5 prefixes the chain config with an optional producer-authority
    // schedule. Older XPR history rows start directly with chain_config. Try
    // the modern layout first, then the legacy field layout; every candidate
    // must consume the row exactly, so malformed rows cannot be accepted by a
    // permissive fallback.
    let modern_error = match decode_global_property_layout(row, true, false) {
        Ok((config, source_chain_id)) => {
            return Ok(PortableRow::GlobalProperty {
                config,
                source_chain_id,
            });
        }
        Err(error) => error,
    };
    let mut row = RowCursor::new(bytes);
    row.varuint()?;
    if let Ok((config, source_chain_id)) = decode_global_property_layout(row, true, true) {
        return Ok(PortableRow::GlobalProperty {
            config,
            source_chain_id,
        });
    }
    let mut row = RowCursor::new(bytes);
    row.varuint()?;
    if let Ok((config, source_chain_id)) = decode_global_property_layout(row, false, true) {
        return Ok(PortableRow::GlobalProperty {
            config,
            source_chain_id,
        });
    }
    Err(modern_error)
}

fn decode_global_property_layout(
    mut row: RowCursor<'_>,
    has_producer_schedule: bool,
    legacy_config_fields: bool,
) -> Result<(ChainConfigV0, [u8; 32]), XprImportError> {
    if has_producer_schedule {
        // proposed_schedule_block_num is optional<uint32>.
        if row.bool()? {
            row.u32()?;
        }
        skip_producer_authority_schedule(&mut row)?;
    }

    let config_version = row.varuint()?;
    if config_version > 1 {
        return Err(bad(format!(
            "unsupported XPR chain_config version {config_version}"
        )));
    }
    let config = ChainConfigV0 {
        max_block_net_usage: row.u64()?,
        target_block_net_usage_pct: row.u32()?,
        max_transaction_net_usage: row.u32()?,
        base_per_transaction_net_usage: row.u32()?,
        net_usage_leeway: row.u32()?,
        context_free_discount_net_usage_num: row.u32()?,
        context_free_discount_net_usage_den: row.u32()?,
        max_block_cpu_usage: row.u32()?,
        target_block_cpu_usage_pct: row.u32()?,
        max_transaction_cpu_usage: row.u32()?,
        min_transaction_cpu_usage: row.u32()?,
        max_transaction_lifetime: row.u32()?,
        deferred_trx_expiration_window: if legacy_config_fields { 0 } else { row.u32()? },
        max_transaction_delay: if legacy_config_fields { 0 } else { row.u32()? },
        max_inline_action_size: row.u32()?,
        max_inline_action_depth: row.u16()?,
        max_authority_depth: row.u16()?,
    };
    if config_version == 1 {
        // Pulse's action-return limit is a fixed build constant. It is checked
        // below, rather than silently migrating an incompatible execution rule.
        let action_return_limit = row.u32()?;
        if action_return_limit != 256 {
            return Err(bad(format!(
                "XPR max_action_return_value_size {action_return_limit} is incompatible with Pulse's fixed 256"
            )));
        }
    }

    let source_chain_id = row.fixed::<32>()?;
    // `wasm_configuration` is a binary extension in Leap 5: it has no
    // presence boolean, and is simply absent in the XPR-core pinned format.
    if row.remaining() != 0 {
        let wasm_version = row.varuint()?;
        if wasm_version != 0 {
            return Err(bad(format!(
                "unsupported XPR wasm_config version {wasm_version}"
            )));
        }
        for _ in 0..11 {
            row.u32()?;
        }
    }
    row.finish()?;
    Ok((config, source_chain_id))
}

fn skip_producer_authority_schedule(row: &mut RowCursor<'_>) -> Result<(), XprImportError> {
    row.u32()?; // schedule version
    let producers = usize::try_from(row.varuint()?)
        .map_err(|_| bad("XPR producer schedule count does not fit this platform"))?;
    if producers > 10_000 {
        return Err(bad("XPR producer schedule has too many producers"));
    }
    for _ in 0..producers {
        row.u64()?; // producer name
        if row.varuint()? != 0 {
            return Err(bad("XPR producer uses unsupported block-signing authority"));
        }
        row.u32()?; // threshold
        let keys = usize::try_from(row.varuint()?)
            .map_err(|_| bad("XPR producer key count does not fit this platform"))?;
        if keys > 10_000 {
            return Err(bad("XPR producer has too many signing keys"));
        }
        for _ in 0..keys {
            if row.varuint()? != 0 {
                return Err(bad("XPR producer uses a non-K1 signing key"));
            }
            row.fixed::<33>()?;
            row.u16()?;
        }
    }
    Ok(())
}

fn decode_protocol_state(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    let feature_count = row.varuint()?;
    if feature_count > 10_000 {
        return Err(bad("XPR protocol-state feature count is too large"));
    }
    let mut features = Vec::with_capacity(feature_count as usize);
    let mut seen_digests = HashSet::with_capacity(feature_count as usize);
    let mut previous_activation_block = None;
    for _ in 0..feature_count {
        row.version()?;
        let feature_digest = row.fixed::<32>()?;
        let activation_block_num = row.u32()?;
        if !seen_digests.insert(feature_digest) {
            return Err(bad(
                "XPR protocol-state contains a duplicate feature digest",
            ));
        }
        if let Some(previous) = previous_activation_block
            && activation_block_num < previous
        {
            return Err(bad(
                "XPR protocol-state feature activations are not in block order",
            ));
        }
        previous_activation_block = Some(activation_block_num);
        features.push((feature_digest, activation_block_num));
    }
    row.finish()?;
    Ok(PortableRow::ProtocolState { features })
}

fn decode_permission_link(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    let result = PortableRow::PermissionLink {
        account: row.u64()?,
        code: row.u64()?,
        message_type: row.u64()?,
        required_permission: row.u64()?,
    };
    row.finish()?;
    Ok(result)
}

fn decode_resource_limits(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    let result = PortableRow::ResourceLimits {
        owner: row.u64()?,
        net_weight: row.i64()?,
        cpu_weight: row.i64()?,
        ram_bytes: row.i64()?,
    };
    row.finish()?;
    Ok(result)
}

fn decode_usage_accumulator(row: &mut RowCursor<'_>) -> Result<ImportUsage, XprImportError> {
    row.version()?;
    Ok(ImportUsage {
        last_ordinal: row.u32()?,
        value_ex: row.u64()?,
        consumed: row.u64()?,
    })
}

fn decode_resource_usage(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    let result = PortableRow::ResourceUsage {
        owner: row.u64()?,
        net_usage: decode_usage_accumulator(&mut row)?,
        cpu_usage: decode_usage_accumulator(&mut row)?,
        ram_usage: row.u64()?,
    };
    row.finish()?;
    Ok(result)
}

fn decode_resource_state(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    let result = PortableRow::ResourceState {
        net: decode_usage_accumulator(&mut row)?,
        cpu: decode_usage_accumulator(&mut row)?,
        total_net_weight: row.u64()?,
        total_cpu_weight: row.u64()?,
        total_ram_bytes: row.u64()?,
        virtual_net_limit: row.u64()?,
        virtual_cpu_limit: row.u64()?,
    };
    row.finish()?;
    Ok(result)
}

fn decode_resource_config(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    let cpu = decode_elastic_params(&mut row)?;
    let net = decode_elastic_params(&mut row)?;
    let result = PortableRow::ResourceConfig {
        cpu,
        net,
        cpu_window: row.u32()?,
        net_window: row.u32()?,
    };
    row.finish()?;
    Ok(result)
}

fn decode_elastic_params(
    row: &mut RowCursor<'_>,
) -> Result<crate::backend::ElasticParams, XprImportError> {
    row.version()?;
    let target = row.u64()?;
    let max = row.u64()?;
    let periods = row.u32()?;
    let max_multiplier = row.u32()?;
    let contract = decode_resource_ratio(row)?;
    let expand = decode_resource_ratio(row)?;
    Ok(crate::backend::ElasticParams {
        target,
        max,
        periods,
        max_multiplier,
        contract,
        expand,
    })
}

fn decode_resource_ratio(row: &mut RowCursor<'_>) -> Result<(u64, u64), XprImportError> {
    row.version()?;
    Ok((row.u64()?, row.u64()?))
}

fn decode_account(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    let name = row.u64()?;
    let creation_date = row.u32()?;
    let abi = row.bytes()?;
    row.finish()?;
    Ok(PortableRow::Account {
        name,
        creation_date,
        abi,
    })
}

fn decode_account_metadata(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    let name = row.u64()?;
    let privileged = row.bool()?;
    let last_code_update = row.i64()?;
    let code = if row.bool()? {
        Some(CodeReference {
            vm_type: row.byte()?,
            vm_version: row.byte()?,
            hash: row.fixed()?,
        })
    } else {
        None
    };
    row.finish()?;
    Ok(PortableRow::AccountMetadata {
        name,
        privileged,
        last_code_update,
        code,
    })
}

fn decode_code(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    let vm_type = row.byte()?;
    let vm_version = row.byte()?;
    let hash = row.fixed()?;
    let code = row.bytes()?;
    row.finish()?;
    Ok(PortableRow::Code {
        hash,
        code,
        vm_type,
        vm_version,
    })
}

fn decode_permission(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    let owner = row.u64()?;
    let name = row.u64()?;
    let parent_name = row.u64()?;
    let last_updated = row.i64()?;
    let authority = decode_authority(&mut row)?;
    row.finish()?;
    Ok(PortableRow::Permission {
        owner,
        name,
        parent_name,
        last_updated,
        authority,
    })
}

fn decode_authority(row: &mut RowCursor<'_>) -> Result<Vec<u8>, XprImportError> {
    let threshold = row.u32()?;
    let key_count =
        usize::try_from(row.varuint()?).map_err(|_| bad("authority key count too large"))?;
    let mut out = Vec::new();
    out.extend_from_slice(&threshold.to_le_bytes());
    out.extend_from_slice(&(key_count as u32).to_le_bytes());
    for _ in 0..key_count {
        let key_type = row.varuint()?;
        let point = row.fixed::<33>()?;
        let mut packed_key = Vec::with_capacity(64);
        match key_type {
            0 | 1 => {
                packed_key.push(key_type as u8);
                packed_key.extend_from_slice(&point);
            }
            2 => {
                let user_presence = row.byte()?;
                if user_presence > 2 {
                    return Err(bad(format!(
                        "XPR WebAuthn authority has invalid user-presence policy {user_presence}"
                    )));
                }
                let rpid = row.bytes()?;
                if rpid.is_empty() || std::str::from_utf8(&rpid).is_err() {
                    return Err(bad("XPR WebAuthn authority has an invalid RP ID"));
                }
                packed_key.push(2);
                packed_key.extend_from_slice(&point);
                packed_key.push(user_presence);
                write_varuint(rpid.len() as u64, &mut packed_key);
                packed_key.extend_from_slice(&rpid);
            }
            _ => {
                return Err(bad(format!(
                    "XPR authority contains unsupported public-key type {key_type}"
                )));
            }
        }
        let weight = row.u16()?;
        out.extend_from_slice(&(packed_key.len() as u32).to_le_bytes());
        out.extend_from_slice(&packed_key);
        out.extend_from_slice(&weight.to_le_bytes());
    }
    let account_count =
        usize::try_from(row.varuint()?).map_err(|_| bad("authority account count too large"))?;
    out.extend_from_slice(&(account_count as u32).to_le_bytes());
    for _ in 0..account_count {
        out.extend_from_slice(&row.u64()?.to_le_bytes());
        out.extend_from_slice(&row.u64()?.to_le_bytes());
        out.extend_from_slice(&row.u16()?.to_le_bytes());
    }
    let wait_count =
        usize::try_from(row.varuint()?).map_err(|_| bad("authority wait count too large"))?;
    out.extend_from_slice(&(wait_count as u32).to_le_bytes());
    for _ in 0..wait_count {
        out.extend_from_slice(&row.u32()?.to_le_bytes());
        out.extend_from_slice(&row.u16()?.to_le_bytes());
    }
    Ok(out)
}

fn decode_contract_table(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    let result = PortableRow::ContractTable {
        code: row.u64()?,
        scope: row.u64()?,
        table: row.u64()?,
        payer: row.u64()?,
    };
    row.finish()?;
    Ok(result)
}

fn decode_contract_row(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    let result = PortableRow::ContractRow {
        code: row.u64()?,
        scope: row.u64()?,
        table: row.u64()?,
        primary: row.u64()?,
        payer: row.u64()?,
        value: row.bytes()?,
    };
    row.finish()?;
    Ok(result)
}

fn secondary_header(row: &mut RowCursor<'_>) -> Result<(u64, u64, u64, u64, u64), XprImportError> {
    row.version()?;
    Ok((row.u64()?, row.u64()?, row.u64()?, row.u64()?, row.u64()?))
}

fn decode_index64(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    let (code, scope, table, primary, payer) = secondary_header(&mut row)?;
    let secondary = row.u64()?;
    row.finish()?;
    Ok(PortableRow::Index64 {
        code,
        scope,
        table,
        primary,
        payer,
        secondary,
    })
}

fn decode_index128(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    let (code, scope, table, primary, payer) = secondary_header(&mut row)?;
    let lo = row.u64()?;
    let hi = row.u64()?;
    row.finish()?;
    Ok(PortableRow::Index128 {
        code,
        scope,
        table,
        primary,
        payer,
        secondary: (lo as u128) | ((hi as u128) << 64),
    })
}

fn decode_index256(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    let (code, scope, table, primary, payer) = secondary_header(&mut row)?;
    let mut secondary = row.fixed::<32>()?;
    secondary[..16].reverse();
    secondary[16..].reverse();
    row.finish()?;
    Ok(PortableRow::Index256 {
        code,
        scope,
        table,
        primary,
        payer,
        secondary: U256 { value: secondary },
    })
}

fn decode_index_double(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    let (code, scope, table, primary, payer) = secondary_header(&mut row)?;
    let secondary = row.u64()?;
    row.finish()?;
    Ok(PortableRow::IndexDouble {
        code,
        scope,
        table,
        primary,
        payer,
        secondary,
    })
}

fn decode_index_long_double(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    let (code, scope, table, primary, payer) = secondary_header(&mut row)?;
    let secondary = Float128 {
        lo: row.u64()?,
        hi: row.u64()?,
    };
    row.finish()?;
    Ok(PortableRow::IndexLongDouble {
        code,
        scope,
        table,
        primary,
        payer,
        secondary,
    })
}

/// Decode the first full-state entry from an XPR `chain_state_history.log`.
///
/// The exporter starts with an empty history directory, so its first record is
/// necessarily the source snapshot's full logical state plus the one accepted
/// block that caused state history to flush it. It is intentionally rejected if
/// framing disagrees with XPR Leap's writer instead of attempting recovery from
/// a partially written export.
pub fn parse_initial_state_history_log(bytes: &[u8]) -> Result<StateHistoryEntry, XprImportError> {
    if bytes.len() < LOG_HEADER_LEN + PAYLOAD_FORMAT_LEN + LOG_TRAILER_LEN {
        return Err(bad("state-history log is too short"));
    }

    let magic = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    if (magic as u16) != 0 {
        return Err(bad(format!(
            "unsupported XPR state-history version {}",
            magic as u16
        )));
    }

    let mut block_id = [0u8; 32];
    block_id.copy_from_slice(&bytes[8..40]);
    let payload_len = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
    let payload_len = usize::try_from(payload_len)
        .map_err(|_| bad("state-history payload length does not fit this platform"))?;
    let entry_end = LOG_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|n| n.checked_add(LOG_TRAILER_LEN))
        .ok_or_else(|| bad("state-history payload length overflows"))?;
    if entry_end > bytes.len() {
        return Err(bad("state-history payload is truncated"));
    }

    let payload = &bytes[LOG_HEADER_LEN..LOG_HEADER_LEN + payload_len];
    let compressed = match payload {
        // Legacy XPR core snapshots: `uint32 compressed_size` plus
        // zlib bytes. Retain this framing for source snapshots from that node.
        payload
            if payload.len() >= PAYLOAD_FORMAT_LEN
                && u32::from_le_bytes(payload[0..PAYLOAD_FORMAT_LEN].try_into().unwrap())
                    as usize
                    == payload.len() - PAYLOAD_FORMAT_LEN =>
        {
            &payload[PAYLOAD_FORMAT_LEN..]
        }
        // Leap 5: `uint32 format=1`, `uint64 decompressed_size`, then zlib
        // bytes. The source writes the uncompressed length so a SHiP server
        // can announce it before inflating the stream.
        payload
            if payload.len() >= PAYLOAD_FORMAT_LEN + DECOMPRESSED_SIZE_LEN
                && u32::from_le_bytes(payload[0..PAYLOAD_FORMAT_LEN].try_into().unwrap()) == 1 =>
        {
            let claimed_len = u64::from_le_bytes(
                payload[PAYLOAD_FORMAT_LEN..PAYLOAD_FORMAT_LEN + DECOMPRESSED_SIZE_LEN]
                    .try_into()
                    .unwrap(),
            );
            if claimed_len > MAX_DECOMPRESSED_DELTA_LEN {
                return Err(bad(format!(
                    "state-history claimed delta exceeds {} byte import limit",
                    MAX_DECOMPRESSED_DELTA_LEN
                )));
            }
            &payload[PAYLOAD_FORMAT_LEN + DECOMPRESSED_SIZE_LEN..]
        }
        payload if payload.len() < PAYLOAD_FORMAT_LEN => {
            return Err(bad("state-history payload is missing format marker"));
        }
        payload => {
            return Err(bad(format!(
                "unsupported state-history payload framing marker {}",
                u32::from_le_bytes(payload[0..PAYLOAD_FORMAT_LEN].try_into().unwrap())
            )));
        }
    };

    let record_pos = u64::from_le_bytes(
        bytes[LOG_HEADER_LEN + payload_len..entry_end]
            .try_into()
            .unwrap(),
    );
    if record_pos != 0 {
        return Err(bad(format!(
            "first state-history record has offset {record_pos}, expected 0"
        )));
    }

    let mut decoder = ZlibDecoder::new(compressed);
    let mut raw = Vec::new();
    decoder
        .by_ref()
        .take(MAX_DECOMPRESSED_DELTA_LEN + 1)
        .read_to_end(&mut raw)
        .map_err(|e| bad(format!("decompressing state-history delta: {e}")))?;
    if raw.len() as u64 > MAX_DECOMPRESSED_DELTA_LEN {
        return Err(bad(format!(
            "state-history delta exceeds {} byte import limit",
            MAX_DECOMPRESSED_DELTA_LEN
        )));
    }

    Ok(StateHistoryEntry {
        magic,
        block_id,
        deltas: parse_table_deltas(&raw)?,
    })
}

/// Inspect up to `max_post_snapshot_entries` after the initial full-state
/// record. A zero limit only validates the first record's framing.
pub fn inspect_state_history_log(
    path: impl AsRef<Path>,
    max_post_snapshot_entries: u64,
) -> Result<StateHistoryWindowSummary, XprImportError> {
    let mut file = File::open(path.as_ref())
        .map_err(|error| bad(format!("opening state-history log: {error}")))?;
    let mut offset = 0u64;
    let mut entry_number = 0u64;
    let mut first_block_id = None;
    let mut last_block_id = [0u8; 32];
    let mut first_payload_bytes = 0u64;
    let mut table_rows = BTreeMap::new();
    let mut generated_transactions = 0u64;
    let mut post_snapshot_entries = 0u64;
    let mut complete = true;
    let mut previous_block_num: Option<u32> = None;

    loop {
        let mut header = [0u8; LOG_HEADER_LEN];
        match file.read(&mut header[..1]) {
            Ok(0) => break,
            Ok(1) => {}
            Ok(_) => unreachable!(),
            Err(error) => return Err(bad(format!("reading state-history header: {error}"))),
        }
        file.read_exact(&mut header[1..])
            .map_err(|error| bad(format!("truncated state-history header: {error}")))?;
        let magic = u64::from_le_bytes(header[0..8].try_into().unwrap());
        if (magic as u16) != 0 {
            return Err(bad(format!(
                "unsupported XPR state-history version {}",
                magic as u16
            )));
        }
        let mut block_id = [0u8; 32];
        block_id.copy_from_slice(&header[8..40]);
        let payload_len = u64::from_le_bytes(header[40..48].try_into().unwrap());
        let payload_len_usize = usize::try_from(payload_len)
            .map_err(|_| bad("state-history payload length does not fit this platform"))?;
        let next_offset = offset
            .checked_add(LOG_HEADER_LEN as u64)
            .and_then(|n| n.checked_add(payload_len))
            .and_then(|n| n.checked_add(LOG_TRAILER_LEN as u64))
            .ok_or_else(|| bad("state-history record offset overflows"))?;

        let block_num = u32::from_be_bytes(block_id[..4].try_into().unwrap());
        if let Some(previous) = previous_block_num
            && block_num != previous.saturating_add(1)
        {
            return Err(bad(format!(
                "state-history block sequence jumps from {previous} to {block_num}"
            )));
        }
        previous_block_num = Some(block_num);

        if entry_number == 0 {
            first_block_id = Some(block_id);
            first_payload_bytes = payload_len;
            file.seek(SeekFrom::Current(i64::try_from(payload_len).map_err(
                |_| bad("state-history payload offset does not fit i64"),
            )?))
            .map_err(|error| bad(format!("skipping initial state payload: {error}")))?;
        } else if post_snapshot_entries < max_post_snapshot_entries {
            let mut payload = vec![0u8; payload_len_usize];
            file.read_exact(&mut payload)
                .map_err(|error| bad(format!("reading state-history payload: {error}")))?;
            for delta in parse_table_deltas(&decompress_state_history_payload(&payload)?)? {
                let rows = delta.rows.len() as u64;
                *table_rows.entry(delta.name.clone()).or_default() += rows;
                if delta.name == "generated_transaction" {
                    generated_transactions += rows;
                }
            }
            post_snapshot_entries += 1;
        } else {
            complete = false;
            file.seek(SeekFrom::Current(i64::try_from(payload_len).map_err(
                |_| bad("state-history payload offset does not fit i64"),
            )?))
            .map_err(|error| bad(format!("skipping bounded-window payload: {error}")))?;
        }

        let mut trailer = [0u8; LOG_TRAILER_LEN];
        file.read_exact(&mut trailer)
            .map_err(|error| bad(format!("truncated state-history record trailer: {error}")))?;
        let recorded_offset = u64::from_le_bytes(trailer);
        if recorded_offset != offset {
            return Err(bad(format!(
                "state-history record at offset {offset} carries trailer offset {recorded_offset}"
            )));
        }
        offset = next_offset;
        last_block_id = block_id;
        entry_number += 1;

        if entry_number >= 1 && post_snapshot_entries == max_post_snapshot_entries {
            let mut probe = [0u8; 1];
            match file.read(&mut probe) {
                Ok(0) => break,
                Ok(1) => {
                    complete = false;
                    file.seek(SeekFrom::Current(-1))
                        .map_err(|error| bad(format!("rewinding history probe: {error}")))?;
                    break;
                }
                Ok(_) => unreachable!(),
                Err(error) => return Err(bad(format!("probing state-history log: {error}"))),
            }
        }
    }

    let first_block_id = first_block_id.ok_or_else(|| bad("state-history log is empty"))?;
    Ok(StateHistoryWindowSummary {
        first_block_id,
        first_payload_bytes,
        entries: entry_number,
        post_snapshot_entries,
        last_block_id,
        table_rows,
        generated_transactions,
        complete,
    })
}

fn decompress_state_history_payload(payload: &[u8]) -> Result<Vec<u8>, XprImportError> {
    let compressed = match payload {
        payload
            if payload.len() >= PAYLOAD_FORMAT_LEN
                && u32::from_le_bytes(payload[0..PAYLOAD_FORMAT_LEN].try_into().unwrap())
                    as usize
                    == payload.len() - PAYLOAD_FORMAT_LEN =>
        {
            &payload[PAYLOAD_FORMAT_LEN..]
        }
        payload
            if payload.len() >= PAYLOAD_FORMAT_LEN + DECOMPRESSED_SIZE_LEN
                && u32::from_le_bytes(payload[0..PAYLOAD_FORMAT_LEN].try_into().unwrap()) == 1 =>
        {
            let claimed_len = u64::from_le_bytes(
                payload[PAYLOAD_FORMAT_LEN..PAYLOAD_FORMAT_LEN + DECOMPRESSED_SIZE_LEN]
                    .try_into()
                    .unwrap(),
            );
            if claimed_len > MAX_DECOMPRESSED_DELTA_LEN {
                return Err(bad(format!(
                    "state-history claimed delta exceeds {} byte import limit",
                    MAX_DECOMPRESSED_DELTA_LEN
                )));
            }
            &payload[PAYLOAD_FORMAT_LEN + DECOMPRESSED_SIZE_LEN..]
        }
        payload if payload.len() < PAYLOAD_FORMAT_LEN => {
            return Err(bad("state-history payload is missing format marker"));
        }
        payload => {
            return Err(bad(format!(
                "unsupported state-history payload framing marker {}",
                u32::from_le_bytes(payload[0..PAYLOAD_FORMAT_LEN].try_into().unwrap())
            )));
        }
    };
    let mut decoder = ZlibDecoder::new(compressed);
    let mut raw = Vec::new();
    decoder
        .by_ref()
        .take(MAX_DECOMPRESSED_DELTA_LEN + 1)
        .read_to_end(&mut raw)
        .map_err(|error| bad(format!("decompressing state-history delta: {error}")))?;
    if raw.len() as u64 > MAX_DECOMPRESSED_DELTA_LEN {
        return Err(bad(format!(
            "state-history delta exceeds {} byte import limit",
            MAX_DECOMPRESSED_DELTA_LEN
        )));
    }
    Ok(raw)
}

fn parse_table_deltas(bytes: &[u8]) -> Result<Vec<TableDelta>, XprImportError> {
    let mut cursor = Cursor::new(bytes);
    let table_count = cursor.varuint()?;
    let table_count = usize::try_from(table_count)
        .map_err(|_| bad("table-delta count does not fit this platform"))?;
    if table_count > 64 {
        return Err(bad(format!("table-delta count {table_count} exceeds 64")));
    }

    let mut deltas = Vec::with_capacity(table_count);
    for _ in 0..table_count {
        let version = cursor.varuint()?;
        if version != 0 {
            return Err(bad(format!("unsupported table-delta version {version}")));
        }
        let name = cursor.bytes()?;
        let name =
            String::from_utf8(name).map_err(|_| bad("table-delta name is not valid UTF-8"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(bad(format!("invalid table-delta name {name:?}")));
        }

        let row_count = cursor.varuint()?;
        let row_count =
            usize::try_from(row_count).map_err(|_| bad("row count does not fit this platform"))?;
        // Every row has at least a one-byte boolean and a one-byte zero length.
        if row_count > cursor.remaining() / 2 {
            return Err(bad(format!(
                "table {name:?} declares {row_count} rows with only {} bytes remaining",
                cursor.remaining()
            )));
        }

        let mut rows = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            let present = cursor.bool()?;
            let data = cursor.bytes()?;
            rows.push(TableDeltaRow { present, data });
        }
        deltas.push(TableDelta { name, rows });
    }
    if cursor.remaining() != 0 {
        return Err(bad(format!(
            "{} trailing bytes after table deltas",
            cursor.remaining()
        )));
    }
    Ok(deltas)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

/// Bounded reader for one type-specific state-history row. Keeping it separate
/// from the outer table-delta reader makes an exact row-consumption check
/// mandatory for every table mapping.
struct RowCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> RowCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn byte(&mut self) -> Result<u8, XprImportError> {
        let value = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| bad("truncated XPR state-history row"))?;
        self.pos += 1;
        Ok(value)
    }

    fn bool(&mut self) -> Result<bool, XprImportError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(bad(format!("invalid XPR state-history boolean {value}"))),
        }
    }

    fn version(&mut self) -> Result<(), XprImportError> {
        let version = self.varuint()?;
        if version != 0 {
            return Err(bad(format!("unsupported XPR row version {version}")));
        }
        Ok(())
    }

    fn varuint(&mut self) -> Result<u64, XprImportError> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            let part = (byte & 0x7f) as u64;
            if shift == 63 && part > 1 {
                return Err(bad("XPR row varuint overflows u64"));
            }
            value |= part << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(bad("XPR row varuint is too long"))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], XprImportError> {
        let end = self
            .pos
            .checked_add(N)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| bad("truncated XPR state-history fixed-width field"))?;
        let value = self.bytes[self.pos..end].try_into().unwrap();
        self.pos = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, XprImportError> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }

    fn u16(&mut self) -> Result<u16, XprImportError> {
        Ok(u16::from_le_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, XprImportError> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }

    fn i64(&mut self) -> Result<i64, XprImportError> {
        Ok(i64::from_le_bytes(self.fixed()?))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, XprImportError> {
        let len = self.varuint()?;
        let len = usize::try_from(len)
            .map_err(|_| bad("XPR row byte length does not fit this platform"))?;
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| bad("truncated XPR state-history byte field"))?;
        let value = self.bytes[self.pos..end].to_vec();
        self.pos = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), XprImportError> {
        if self.pos != self.bytes.len() {
            return Err(bad(format!(
                "{} trailing bytes in XPR state-history row",
                self.bytes.len() - self.pos
            )));
        }
        Ok(())
    }
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn byte(&mut self) -> Result<u8, XprImportError> {
        let value = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| bad("unexpected end of table-delta stream"))?;
        self.pos += 1;
        Ok(value)
    }

    fn bool(&mut self) -> Result<bool, XprImportError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(bad(format!("invalid table-delta boolean {value}"))),
        }
    }

    fn varuint(&mut self) -> Result<u64, XprImportError> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            let part = (byte & 0x7f) as u64;
            if shift == 63 && part > 1 {
                return Err(bad("table-delta varuint overflows u64"));
            }
            value |= part << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(bad("table-delta varuint is too long"))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, XprImportError> {
        let len = self.varuint()?;
        let len = usize::try_from(len)
            .map_err(|_| bad("table-delta byte length does not fit this platform"))?;
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| bad("table-delta byte payload is truncated"))?;
        let result = self.bytes[self.pos..end].to_vec();
        self.pos = end;
        Ok(result)
    }
}

fn bad(message: impl Into<String>) -> XprImportError {
    XprImportError(message.into())
}

fn write_varuint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{
        Compression,
        write::ZlibEncoder,
    };
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn accepts_current_and_legacy_global_property_rows() {
        let current = hex::decode("01000000000000010000100000000000e8030000000008000c000000f40100001400000064000000400d0300e8030000f049020064000000100e00005802000080533b000010000004000600000100009371fb05f023fcc78b23923d70bdfe6642cdf1956d120045bcd1371e05c961a90000040000000400000020000000000100002000000004000000200000000040010000400110020000fb000000").unwrap();
        let PortableRow::GlobalProperty { config, .. } = decode_global_property(&current).unwrap()
        else {
            panic!("expected global_property row");
        };
        assert_eq!(config.deferred_trx_expiration_window, 600);
        assert_eq!(config.max_transaction_delay, 3_888_000);

        let legacy = hex::decode("01010000100000000000e8030000000008000c000000f40100001400000064000000005ed0b2c409000000ca9a3ba0860100100e000000100000060006000001000098f998d9010e744bddcef4a12ac306b93919537caa232ca19de2ed50322bb6fa0000040000000400000020000000000100002000000004000000200000000040010000400110020000fb000000").unwrap();
        let PortableRow::GlobalProperty { config, .. } = decode_global_property(&legacy).unwrap()
        else {
            panic!("expected legacy global_property row");
        };
        assert_eq!(config.deferred_trx_expiration_window, 0);
        assert_eq!(config.max_transaction_delay, 0);
    }

    #[test]
    fn parses_full_state_history_entry() {
        // Two table_delta values: account has one live payload, and code has a
        // single empty removal. Hydration later rejects that removal; decoding
        // preserves it so validation can report the source error precisely.
        let raw = [
            2, // table count
            0, 7, b'a', b'c', b'c', b'o', b'u', b'n', b't', 1, 1, 3, 1, 2, 3, 0, 4, b'c', b'o',
            b'd', b'e', 1, 0, 0,
        ];
        let mut compressed = ZlibEncoder::new(Vec::new(), Compression::default());
        compressed.write_all(&raw).unwrap();
        let compressed = compressed.finish().unwrap();

        let mut log = Vec::new();
        log.extend_from_slice(&0u64.to_le_bytes()); // SHiP version 0
        log.extend_from_slice(&[0xabu8; 32]);
        log.extend_from_slice(&((4 + compressed.len()) as u64).to_le_bytes());
        log.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        log.extend_from_slice(&compressed);
        log.extend_from_slice(&0u64.to_le_bytes()); // first entry offset

        let entry = parse_initial_state_history_log(&log).unwrap();
        assert_eq!(entry.block_id, [0xabu8; 32]);
        assert_eq!(entry.deltas.len(), 2);
        assert_eq!(entry.deltas[0].name, "account");
        assert_eq!(entry.deltas[0].rows[0].data, vec![1, 2, 3]);
        assert!(!entry.deltas[1].rows[0].present);
    }

    #[test]
    fn parses_leap_5_state_history_entry() {
        let raw = [0]; // zero table deltas
        let mut compressed = ZlibEncoder::new(Vec::new(), Compression::default());
        compressed.write_all(&raw).unwrap();
        let compressed = compressed.finish().unwrap();

        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes()); // Leap 5 framing
        payload.extend_from_slice(&(raw.len() as u64).to_le_bytes());
        payload.extend_from_slice(&compressed);

        let mut log = Vec::new();
        log.extend_from_slice(&0u64.to_le_bytes()); // SHiP version 0
        log.extend_from_slice(&[0xcdu8; 32]);
        log.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        log.extend_from_slice(&payload);
        log.extend_from_slice(&0u64.to_le_bytes()); // first entry offset

        let entry = parse_initial_state_history_log(&log).unwrap();
        assert_eq!(entry.block_id, [0xcdu8; 32]);
        assert!(entry.deltas.is_empty());
    }

    #[test]
    fn inspects_bounded_history_window_without_decoding_initial_state() {
        fn record(block_num: u32, raw: &[u8], offset: u64) -> Vec<u8> {
            let mut compressed = ZlibEncoder::new(Vec::new(), Compression::default());
            compressed.write_all(raw).unwrap();
            let compressed = compressed.finish().unwrap();
            let mut payload = Vec::new();
            payload.extend_from_slice(&1u32.to_le_bytes());
            payload.extend_from_slice(&(raw.len() as u64).to_le_bytes());
            payload.extend_from_slice(&compressed);
            let mut out = Vec::new();
            out.extend_from_slice(&0u64.to_le_bytes());
            let mut block_id = [0u8; 32];
            block_id[..4].copy_from_slice(&block_num.to_be_bytes());
            out.extend_from_slice(&block_id);
            out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            out.extend_from_slice(&payload);
            out.extend_from_slice(&offset.to_le_bytes());
            out
        }

        let first = record(100, &[0], 0);
        let second_offset = first.len() as u64;
        let first_payload_bytes = first.len() as u64 - 48 - 8;
        let mut second_raw = vec![1, 0, 7];
        second_raw.extend_from_slice(b"account");
        second_raw.extend_from_slice(&1u8.to_le_bytes());
        second_raw.extend_from_slice(&[1, 0]);
        let second = record(101, &second_raw, second_offset);
        let log = [first, second].concat();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("chain_state_history.log");
        std::fs::write(&path, log).unwrap();

        let summary = inspect_state_history_log(&path, 1).unwrap();
        assert_eq!(summary.entries, 2);
        assert_eq!(summary.post_snapshot_entries, 1);
        assert!(summary.complete);
        assert_eq!(summary.table_rows.get("account"), Some(&1));
        assert_eq!(summary.first_payload_bytes, first_payload_bytes);
    }

    #[test]
    fn rejects_inconsistent_compressed_length() {
        let mut log = vec![0u8; LOG_HEADER_LEN];
        log[40..48].copy_from_slice(&4u64.to_le_bytes());
        log.extend_from_slice(&1u32.to_le_bytes());
        log.extend_from_slice(&[0, 0, 0]);
        log.extend_from_slice(&0u64.to_le_bytes());
        assert!(parse_initial_state_history_log(&log).is_err());
    }

    #[test]
    fn rejects_overlong_varuint() {
        let bytes = [0x80; 10];
        assert!(parse_table_deltas(&bytes).is_err());
    }

    #[test]
    fn rejects_duplicate_or_out_of_order_protocol_features() {
        let mut duplicate = vec![0, 2, 0];
        duplicate.extend_from_slice(&[7; 32]);
        duplicate.extend_from_slice(&10u32.to_le_bytes());
        duplicate.push(0);
        duplicate.extend_from_slice(&[7; 32]);
        duplicate.extend_from_slice(&11u32.to_le_bytes());
        assert!(matches!(
            decode_protocol_state(&duplicate),
            Err(ref error) if error.to_string().contains("duplicate feature digest")
        ));

        let mut out_of_order = vec![0, 2, 0];
        out_of_order.extend_from_slice(&[8; 32]);
        out_of_order.extend_from_slice(&20u32.to_le_bytes());
        out_of_order.push(0);
        out_of_order.extend_from_slice(&[9; 32]);
        out_of_order.extend_from_slice(&19u32.to_le_bytes());
        assert!(matches!(
            decode_protocol_state(&out_of_order),
            Err(ref error) if error.to_string().contains("not in block order")
        ));
    }

    #[test]
    fn hydrates_portable_accounts_and_all_contract_index_types() {
        let account = 11u64;
        let code = 22u64;
        let scope = 33u64;
        let table = 44u64;
        let payer = 55u64;
        let code_hash = [0x5au8; 32];

        let mut account_row = vec![0];
        account_row.extend_from_slice(&account.to_le_bytes());
        account_row.extend_from_slice(&7u32.to_le_bytes());
        bytes(&mut account_row, &[0xaa, 0xbb]);

        let mut metadata_row = vec![0];
        metadata_row.extend_from_slice(&account.to_le_bytes());
        metadata_row.push(1); // privileged
        metadata_row.extend_from_slice(&0i64.to_le_bytes());
        metadata_row.push(1); // has code
        metadata_row.push(0); // vm type
        metadata_row.push(0); // vm version
        metadata_row.extend_from_slice(&code_hash);

        let mut code_row = vec![0, 0, 0]; // version, vm type, vm version
        code_row.extend_from_slice(&code_hash);
        bytes(&mut code_row, &[0, 97, 115, 109]);

        let mut permission_row = vec![0];
        permission_row.extend_from_slice(&account.to_le_bytes());
        permission_row.extend_from_slice(&111u64.to_le_bytes());
        permission_row.extend_from_slice(&0u64.to_le_bytes());
        permission_row.extend_from_slice(&0i64.to_le_bytes());
        permission_row.extend_from_slice(&0u32.to_le_bytes()); // authority threshold
        permission_row.extend_from_slice(&[0, 0, 0]); // key/account/wait counts

        let mut table_row = vec![0];
        for value in [code, scope, table, payer] {
            table_row.extend_from_slice(&value.to_le_bytes());
        }

        let mut kv_row = secondary_prefix(code, scope, table, 66, payer);
        bytes(&mut kv_row, &[1, 2, 3]);

        let mut index64 = secondary_prefix(code, scope, table, 67, payer);
        index64.extend_from_slice(&77u64.to_le_bytes());

        let mut index128 = secondary_prefix(code, scope, table, 68, payer);
        index128.extend_from_slice(&88u64.to_le_bytes());
        index128.extend_from_slice(&99u64.to_le_bytes());

        let mut index256 = secondary_prefix(code, scope, table, 69, payer);
        let desired_256: Vec<u8> = (0..32).collect();
        let mut first: [u8; 16] = desired_256[..16].try_into().unwrap();
        let mut second: [u8; 16] = desired_256[16..].try_into().unwrap();
        first.reverse();
        second.reverse();
        index256.extend_from_slice(&first);
        index256.extend_from_slice(&second);

        let mut index_double = secondary_prefix(code, scope, table, 70, payer);
        index_double.extend_from_slice(&1.5f64.to_bits().to_le_bytes());

        let mut index_long_double = secondary_prefix(code, scope, table, 71, payer);
        index_long_double.extend_from_slice(&101u64.to_le_bytes());
        index_long_double.extend_from_slice(&202u64.to_le_bytes());

        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [0; 32],
            deltas: vec![
                delta("account", account_row),
                delta("account_metadata", metadata_row),
                delta("code", code_row),
                delta("permission", permission_row),
                delta("contract_table", table_row),
                delta("contract_row", kv_row),
                delta("contract_index64", index64),
                delta("contract_index128", index128),
                delta("contract_index256", index256),
                delta("contract_index_double", index_double),
                delta("contract_index_long_double", index_long_double),
            ],
        };
        let dir = TempDir::new().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();

        let summary = hydrate_full_state(&mut db, &entry).unwrap();

        assert_eq!(summary.accounts, 1);
        assert_eq!(summary.account_metadata, 1);
        assert_eq!(summary.code_rows, 1);
        assert_eq!(summary.permissions, 1);
        assert_eq!(summary.contract_tables, 1);
        assert_eq!(summary.contract_rows, 1);
        assert_eq!(summary.index64_rows, 1);
        assert_eq!(summary.index128_rows, 1);
        assert_eq!(summary.index256_rows, 1);
        assert_eq!(summary.index_double_rows, 1);
        assert_eq!(summary.index_long_double_rows, 1);
        assert!(db.is_account(account).unwrap());
        assert_eq!(db.arena_account_metadata_privileged(account), Some(true));
        assert_eq!(db.arena_permission(account, 111), Some((0, 0)));
        assert_eq!(
            db.get_code_bytes_by_hash(&code_hash, 0, 0).unwrap(),
            vec![0, 97, 115, 109]
        );
        assert_eq!(db.arena_kv_get(code, scope, table, 66), Some(vec![1, 2, 3]));
        assert_eq!(db.arena_idx64_payer(code, scope, table, 67), Some(payer));
        assert_eq!(db.arena_idx128_payer(code, scope, table, 68), Some(payer));
        assert_eq!(db.arena_idx256_payer(code, scope, table, 69), Some(payer));
        assert_eq!(
            db.arena_idx_double_payer(code, scope, table, 70),
            Some(payer)
        );
        assert_eq!(
            db.arena_idx_long_double_payer(code, scope, table, 71),
            Some(payer)
        );
    }

    #[test]
    fn imports_reserved_permission_without_aliasing_first_usage() {
        fn permission(owner: u64, name: u64) -> Vec<u8> {
            let mut row = vec![0];
            row.extend_from_slice(&owner.to_le_bytes());
            row.extend_from_slice(&name.to_le_bytes());
            row.extend_from_slice(&0u64.to_le_bytes()); // root permission
            row.extend_from_slice(&0i64.to_le_bytes()); // last_updated
            row.extend_from_slice(&0u32.to_le_bytes()); // authority threshold
            row.extend_from_slice(&[0, 0, 0]); // key/account/wait counts
            row
        }

        let real_owner = 11;
        let real_name = 111;
        let reserved = permission(0, 0);
        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [0; 32],
            deltas: vec![TableDelta {
                name: "permission".into(),
                rows: vec![
                    TableDeltaRow {
                        present: true,
                        data: reserved.clone(),
                    },
                    TableDeltaRow {
                        present: true,
                        data: permission(real_owner, real_name),
                    },
                ],
            }],
        };
        let sidecar = DeferredTransactionSidecar {
            version: DeferredTransactionSidecar::VERSION,
            source_block_id: hex::encode(entry.block_id),
            source_chain_id: None,
            account_metadata: vec![],
            code: vec![],
            // Put the sentinel last: applying its aliased usage id would
            // otherwise overwrite the first real permission's timestamp.
            permissions: vec![
                PermissionSidecarRow {
                    owner: real_owner,
                    name: real_name,
                    last_used: 123,
                },
                PermissionSidecarRow {
                    owner: 0,
                    name: 0,
                    last_used: 999,
                },
            ],
            global_action_sequence: 0,
            input_transactions: vec![],
            transactions: vec![],
        };
        let dir = TempDir::new().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();

        let summary =
            hydrate_full_state_with_deferred_transactions(&mut db, &entry, Some(&sidecar)).unwrap();
        assert_eq!(summary.permissions, 2);
        assert_eq!(
            db.read()
                .unwrap()
                .permission_last_used_by_name(real_owner, real_name)
                .unwrap(),
            123
        );
        let packed = parse_table_deltas(&db.pack_deltas(true, &[0; 32])).unwrap();
        let permissions = packed
            .iter()
            .find(|delta| delta.name == "permission")
            .unwrap();
        assert!(permissions.rows.iter().any(|row| row.data == reserved));
    }

    #[test]
    fn imports_sidecar_bookkeeping_fields_after_base_rows() {
        let account = 11u64;
        let code_hash = [0x5au8; 32];
        let mut account_row = vec![0];
        account_row.extend_from_slice(&account.to_le_bytes());
        account_row.extend_from_slice(&7u32.to_le_bytes());
        bytes(&mut account_row, &[]);

        let mut metadata_row = vec![0];
        metadata_row.extend_from_slice(&account.to_le_bytes());
        metadata_row.push(0);
        metadata_row.extend_from_slice(&0i64.to_le_bytes());
        metadata_row.push(1);
        metadata_row.extend_from_slice(&[0, 0]);
        metadata_row.extend_from_slice(&code_hash);

        let mut code_row = vec![0, 0, 0];
        code_row.extend_from_slice(&code_hash);
        bytes(&mut code_row, &[0, 97, 115, 109]);

        let mut permission_row = vec![0];
        permission_row.extend_from_slice(&account.to_le_bytes());
        permission_row.extend_from_slice(&111u64.to_le_bytes());
        permission_row.extend_from_slice(&0u64.to_le_bytes());
        permission_row.extend_from_slice(&0i64.to_le_bytes());
        permission_row.extend_from_slice(&0u32.to_le_bytes());
        permission_row.extend_from_slice(&[0, 0, 0]);

        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [0; 32],
            deltas: vec![
                delta("account", account_row),
                delta("account_metadata", metadata_row),
                delta("code", code_row),
                delta("permission", permission_row),
            ],
        };
        let sidecar = DeferredTransactionSidecar {
            version: DeferredTransactionSidecar::VERSION,
            source_block_id: hex::encode(entry.block_id),
            source_chain_id: None,
            account_metadata: vec![AccountMetadataSidecarRow {
                name: account,
                recv_sequence: 7,
                auth_sequence: 8,
                code_sequence: 9,
                abi_sequence: 10,
            }],
            code: vec![CodeSidecarRow {
                code_hash: hex::encode(code_hash),
                vm_type: 0,
                vm_version: 0,
                code_ref_count: 1,
                first_block_used: 399_000_123,
            }],
            permissions: vec![PermissionSidecarRow {
                owner: account,
                name: 111,
                last_used: 123_456,
            }],
            global_action_sequence: 987_654_321,
            input_transactions: vec![],
            transactions: vec![],
        };
        let dir = TempDir::new().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();

        hydrate_full_state_with_deferred_transactions(&mut db, &entry, Some(&sidecar)).unwrap();
        let metadata = db.arena_account_metadata(account).unwrap();
        assert_eq!(metadata.recv_sequence, 7);
        assert_eq!(metadata.auth_sequence, 8);
        assert_eq!(metadata.code_sequence, 9);
        assert_eq!(metadata.abi_sequence, 10);
        assert_eq!(db.arena_global_action_sequence(), Some(987_654_321));
        assert_eq!(
            db.read()
                .unwrap()
                .permission_last_used_by_name(account, 111)
                .unwrap(),
            123_456
        );
    }

    #[test]
    fn rejects_sidecar_bookkeeping_that_does_not_cover_source_rows() {
        let sidecar = DeferredTransactionSidecar {
            version: DeferredTransactionSidecar::VERSION,
            source_block_id: hex::encode([0; 32]),
            source_chain_id: None,
            account_metadata: vec![AccountMetadataSidecarRow {
                name: 99,
                recv_sequence: 0,
                auth_sequence: 0,
                code_sequence: 0,
                abi_sequence: 0,
            }],
            code: vec![],
            permissions: vec![],
            global_action_sequence: 0,
            input_transactions: vec![],
            transactions: vec![],
        };
        let rows = vec![PortableRow::AccountMetadata {
            name: 11,
            privileged: false,
            last_code_update: 0,
            code: None,
        }];
        let error = validate_sidecar_fields(&rows, Some(&sidecar)).unwrap_err();
        assert!(error.to_string().contains("account_metadata sidecar"));
    }

    #[test]
    fn rejects_sidecar_source_chain_id_mismatch() {
        let sidecar = DeferredTransactionSidecar {
            version: DeferredTransactionSidecar::VERSION,
            source_block_id: hex::encode([0; 32]),
            source_chain_id: Some(hex::encode([2; 32])),
            account_metadata: vec![],
            code: vec![],
            permissions: vec![],
            global_action_sequence: 0,
            input_transactions: vec![],
            transactions: vec![],
        };
        let config = ChainConfigV0 {
            max_block_net_usage: 0,
            target_block_net_usage_pct: 0,
            max_transaction_net_usage: 0,
            base_per_transaction_net_usage: 0,
            net_usage_leeway: 0,
            context_free_discount_net_usage_num: 0,
            context_free_discount_net_usage_den: 0,
            max_block_cpu_usage: 0,
            target_block_cpu_usage_pct: 0,
            max_transaction_cpu_usage: 0,
            min_transaction_cpu_usage: 0,
            max_transaction_lifetime: 0,
            deferred_trx_expiration_window: 0,
            max_transaction_delay: 0,
            max_inline_action_size: 0,
            max_inline_action_depth: 0,
            max_authority_depth: 0,
        };
        let rows = vec![PortableRow::GlobalProperty {
            config,
            source_chain_id: [1; 32],
        }];
        let error = validate_sidecar_fields(&rows, Some(&sidecar)).unwrap_err();
        assert!(error.to_string().contains("source chain id"));
    }

    #[test]
    fn rejects_unsupported_state_without_mutating_arena() {
        let mut account_row = vec![0];
        account_row.extend_from_slice(&11u64.to_le_bytes());
        account_row.extend_from_slice(&7u32.to_le_bytes());
        bytes(&mut account_row, &[]);
        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [0; 32],
            deltas: vec![
                delta("account", account_row),
                delta("global_property", vec![0]),
            ],
        };
        let dir = TempDir::new().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();

        assert!(hydrate_full_state(&mut db, &entry).is_err());
        assert!(!db.is_account(11).unwrap());
    }

    #[test]
    fn rejects_ship_generated_transaction_without_mutating_arena() {
        let mut generated = vec![0]; // generated_transaction_v0
        generated.extend_from_slice(&11u64.to_le_bytes()); // sender
        generated.extend_from_slice(&12u64.to_le_bytes()); // sender_id low
        generated.extend_from_slice(&13u64.to_le_bytes()); // sender_id high
        generated.extend_from_slice(&14u64.to_le_bytes()); // payer
        generated.extend_from_slice(&[15; 32]); // transaction id
        bytes(&mut generated, &[16, 17]); // packed transaction
        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [0; 32],
            deltas: vec![delta("generated_transaction", generated)],
        };
        let dir = TempDir::new().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();

        let error = hydrate_full_state(&mut db, &entry).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("omits delay_until, expiration, and published")
        );
        assert!(!db.is_account(11).unwrap());
    }

    #[test]
    fn imports_deferred_sidecar_into_arena_after_verification() {
        let mut generated = vec![0]; // generated_transaction_v0
        generated.extend_from_slice(&11u64.to_le_bytes()); // sender
        generated.extend_from_slice(&12u64.to_le_bytes()); // sender_id low
        generated.extend_from_slice(&13u64.to_le_bytes()); // sender_id high
        generated.extend_from_slice(&14u64.to_le_bytes()); // payer
        generated.extend_from_slice(&[15; 32]); // transaction id
        bytes(&mut generated, &[16, 17]); // packed transaction
        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [42; 32],
            deltas: vec![delta("generated_transaction", generated)],
        };
        let sidecar_json = format!(
            r#"{{"version":2,"source_block_id":"{}","global_action_sequence":0,"input_transactions":[],"transactions":[{{"sender":11,"sender_id":"{}","payer":14,"trx_id":"{}","delay_until":1,"expiration":2,"published":0,"packed_trx":"1011"}}]}}"#,
            hex::encode(entry.block_id),
            (12u128 | ((13u128) << 64)),
            hex::encode([15; 32]),
        );
        let sidecar = DeferredTransactionSidecar::from_json_bytes(sidecar_json.as_bytes()).unwrap();
        let dir = TempDir::new().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();

        let summary =
            hydrate_full_state_with_deferred_transactions(&mut db, &entry, Some(&sidecar)).unwrap();
        assert_eq!(summary.deferred_transactions, 1);
        assert_eq!(db.deferred_transaction_count(), 1);
        assert!(!db.is_account(11).unwrap());
    }

    #[test]
    fn imports_input_transaction_dedupe_and_global_sequence_from_sidecar() {
        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [42; 32],
            deltas: vec![],
        };
        let trx_id = [0xabu8; 32];
        let sidecar = DeferredTransactionSidecar::from_json_bytes(
            format!(
                r#"{{"version":2,"source_block_id":"{}","global_action_sequence":1637582121,"input_transactions":[{{"trx_id":"{}","expiration":1788894001}}],"transactions":[]}}"#,
                hex::encode(entry.block_id),
                hex::encode(trx_id),
            )
            .as_bytes(),
        )
        .unwrap();
        let dir = TempDir::new().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();

        let summary =
            hydrate_full_state_with_deferred_transactions(&mut db, &entry, Some(&sidecar)).unwrap();

        assert_eq!(summary.input_transactions, 1);
        assert_eq!(db.arena_transaction_count(), 1);
        assert!(db.arena_transaction_exists(&trx_id));
        assert_eq!(db.arena_global_action_sequence(), Some(1_637_582_121));
    }

    #[test]
    fn rejects_legacy_sidecar_without_replay_protection_table() {
        let error = DeferredTransactionSidecar::from_json_bytes(
            br#"{"version":1,"source_block_id":"0000000000000000000000000000000000000000000000000000000000000000","transactions":[]}"#,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid deferred-transaction sidecar JSON")
        );
    }

    #[test]
    fn rejects_duplicate_input_transaction_sidecar_rows() {
        let trx_id = hex::encode([7; 32]);
        let error = DeferredTransactionSidecar::from_json_bytes(
            format!(
                r#"{{"version":2,"source_block_id":"{}","global_action_sequence":0,"input_transactions":[{{"trx_id":"{trx_id}","expiration":1}},{{"trx_id":"{trx_id}","expiration":2}}],"transactions":[]}}"#,
                hex::encode([0; 32]),
            )
            .as_bytes(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate input transaction sidecar row")
        );
    }

    #[test]
    fn applies_delta_deferred_sidecar_transactionally() {
        let mut generated = vec![0];
        generated.extend_from_slice(&11u64.to_le_bytes());
        generated.extend_from_slice(&12u64.to_le_bytes());
        generated.extend_from_slice(&13u64.to_le_bytes());
        generated.extend_from_slice(&14u64.to_le_bytes());
        generated.extend_from_slice(&[15; 32]);
        bytes(&mut generated, &[16, 17]);
        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [43; 32],
            deltas: vec![delta("generated_transaction", generated)],
        };
        let sidecar = DeferredTransactionSidecar::from_json_bytes(
            format!(
                r#"{{"version":2,"source_block_id":"{}","global_action_sequence":0,"input_transactions":[],"transactions":[{{"sender":11,"sender_id":"{}","payer":14,"trx_id":"{}","delay_until":1,"expiration":2,"published":0,"packed_trx":"1011"}}]}}"#,
                hex::encode(entry.block_id),
                (12u128 | ((13u128) << 64)),
                hex::encode([15; 32]),
            )
            .as_bytes(),
        )
        .unwrap();
        let dir = TempDir::new().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();

        let summary =
            apply_state_history_delta_with_sidecar(&mut db, &entry, Some(&sidecar)).unwrap();
        assert_eq!(summary.deferred_transactions, 1);
        assert_eq!(db.deferred_transaction_count(), 1);
    }

    #[test]
    fn delta_sidecar_replaces_omitted_input_transaction_state() {
        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [44; 32],
            deltas: vec![],
        };
        let old_id = [1; 32];
        let new_id = [2; 32];
        let sidecar = DeferredTransactionSidecar::from_json_bytes(
            format!(
                r#"{{"version":2,"source_block_id":"{}","global_action_sequence":99,"input_transactions":[{{"trx_id":"{}","expiration":123}}],"transactions":[]}}"#,
                hex::encode(entry.block_id),
                hex::encode(new_id),
            )
            .as_bytes(),
        )
        .unwrap();
        let dir = TempDir::new().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();
        db.record_transaction(&old_id, 100).unwrap();

        let summary =
            apply_state_history_delta_with_sidecar(&mut db, &entry, Some(&sidecar)).unwrap();

        assert_eq!(summary.input_transactions, 1);
        assert!(!db.arena_transaction_exists(&old_id));
        assert!(db.arena_transaction_exists(&new_id));
        assert_eq!(db.arena_global_action_sequence(), Some(99));
    }

    #[test]
    fn rejects_deferred_sidecar_from_a_different_block() {
        let sidecar = DeferredTransactionSidecar::from_json_bytes(
            br#"{"version":2,"source_block_id":"0000000000000000000000000000000000000000000000000000000000000000","global_action_sequence":0,"input_transactions":[],"transactions":[]}"#,
        )
        .unwrap();
        let error = validate_sidecar_block_id(&sidecar, [1; 32]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match SHiP full-state block")
        );
    }

    #[test]
    fn migration_manifest_rejects_a_different_checkpoint() {
        let checkpoint = crate::snapshot::encode(7, b"first checkpoint");
        let manifest = MigrationManifest::new(
            b"source state history",
            [9; 32],
            &checkpoint,
            7,
            ImportSummary {
                accounts: 3,
                ..Default::default()
            },
        );
        assert!(manifest.verify_checkpoint(&checkpoint).is_ok());
        assert!(
            manifest
                .verify_checkpoint(&crate::snapshot::encode(7, b"other checkpoint"))
                .unwrap_err()
                .contains("does not match manifest")
        );
    }

    #[test]
    fn migration_manifest_verifies_checkpoint_from_path() {
        let checkpoint = crate::snapshot::encode(7, b"checkpoint");
        let manifest = MigrationManifest::new(
            b"source state history",
            [9; 32],
            &checkpoint,
            7,
            ImportSummary::default(),
        );
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("migration.snapshot");
        std::fs::write(&path, checkpoint).unwrap();
        assert!(manifest.verify_checkpoint_path(&path).is_ok());
    }

    #[test]
    fn migration_manifest_commits_deferred_sidecar() {
        let checkpoint = crate::snapshot::encode(7, b"checkpoint");
        let manifest = MigrationManifest::new(
            b"source state history",
            [9; 32],
            &checkpoint,
            7,
            ImportSummary::default(),
        )
        .with_deferred_transaction_sidecar(b"sidecar");
        assert_eq!(
            manifest.deferred_transaction_sidecar_sha256,
            Some(hex::encode(Digest::hash(b"sidecar").as_bytes()))
        );
    }

    fn deferred_row(
        sender: u64,
        trx: u8,
        delay_until: i64,
        expiration: i64,
    ) -> DeferredTransactionSidecarRow {
        DeferredTransactionSidecarRow {
            sender,
            sender_id: "1".to_string(),
            payer: sender,
            trx_id: hex::encode([trx; 32]),
            delay_until,
            expiration,
            published: delay_until - 1_000_000,
            packed_trx: "00".to_string(),
        }
    }

    #[test]
    fn deferred_inventory_rejects_rows_due_in_the_pause_window() {
        // Window (H, P]: block H+1 opens at `start`, the pause head lands
        // at `end` — both in deferred (Unix-microsecond) time.
        let start = 1_700_000_000_000_000i64;
        let end = start + 5_000_000;
        // Due mid-window: fails closed naming the sender and transaction.
        let err = check_no_deferred_due_in_window(
            &[deferred_row(1111, 0xaa, start + 1_000_000, end + 1_000_000)],
            start,
            end,
        )
        .unwrap_err();
        assert!(err.contains("1111"), "naming the sender, got: {err}");
        assert!(
            err.contains(&hex::encode([0xaau8; 32])),
            "naming the transaction, got: {err}"
        );
        // Delay exactly on the pause head still executes in-window.
        assert!(
            check_no_deferred_due_in_window(
                &[deferred_row(1111, 0xab, end, end + 1_000_000)],
                start,
                end
            )
            .is_err(),
            "a delay on the pause head is due in-window"
        );
        // A row whose delay elapsed before H but is still unexpired at the
        // window start fires on the first post-H block: rejected too.
        assert!(
            check_no_deferred_due_in_window(
                &[deferred_row(1111, 0xac, start - 1, start)],
                start,
                end
            )
            .is_err(),
            "a row unexpired at the window start fires in-window"
        );
        // An inverted window is a caller bug: fail closed, not vacuous.
        assert!(check_no_deferred_due_in_window(&[], end, start - 1).is_err());
    }

    #[test]
    fn deferred_inventory_accepts_rows_outside_the_window() {
        let start = 1_700_000_000_000_000i64;
        let end = start + 5_000_000;
        // Due after the pause head: crosses the boundary by design.
        check_no_deferred_due_in_window(
            &[deferred_row(1111, 0xaa, end + 1, end + 1_000_000)],
            start,
            end,
        )
        .expect("a row due after P must cross the boundary");
        // Already expired before the window opens: retired pre-H.
        check_no_deferred_due_in_window(
            &[deferred_row(1111, 0xab, start - 2_000_000, start - 1)],
            start,
            end,
        )
        .expect("a row expired before the window must be accepted");
        // Empty sidecars carry nothing due.
        check_no_deferred_due_in_window(&[], start, end).expect("empty inventory is accepted");
        // A pause that lands exactly on H attests an empty window: only a
        // row due exactly then fails.
        check_no_deferred_due_in_window(
            &[deferred_row(1111, 0xac, start + 1, start + 1_000_000)],
            start,
            start,
        )
        .expect("an empty window accepts later rows");
        assert!(
            check_no_deferred_due_in_window(
                &[deferred_row(1111, 0xad, start, start + 1_000_000)],
                start,
                start
            )
            .is_err(),
            "a row due exactly at H fires on the boundary"
        );
    }

    fn arena_row(
        sender: u64,
        trx: u8,
        delay_until: i64,
        expiration: i64,
    ) -> crate::backend::DeferredTransaction {
        crate::backend::DeferredTransaction {
            sender,
            sender_id: 1,
            payer: sender,
            trx_id: [trx; 32],
            delay_until,
            expiration,
            published: delay_until - 1_000_000,
            packed_trx: vec![0],
        }
    }

    #[test]
    fn restore_inventory_rejects_arena_rows_due_in_the_pause_window() {
        let start = 1_700_000_000_000_000i64;
        let end = start + 5_000_000;
        let err = check_no_arena_deferred_due_in_window(
            &[arena_row(2222, 0xbb, start + 1_000_000, end + 1_000_000)],
            start,
            end,
        )
        .unwrap_err();
        assert!(err.contains("2222"), "naming the sender, got: {err}");
        assert!(
            err.contains(&hex::encode([0xbbu8; 32])),
            "naming the transaction, got: {err}"
        );
        // Rows outside the window and empty restores boot.
        check_no_arena_deferred_due_in_window(
            &[arena_row(2222, 0xbb, end + 1, end + 1_000_000)],
            start,
            end,
        )
        .expect("a row due after P must boot");
        check_no_arena_deferred_due_in_window(&[], start, end).expect("no rows must boot");
        assert!(check_no_arena_deferred_due_in_window(&[], end, start - 1).is_err());
    }

    #[test]
    fn pause_window_bounds_come_from_the_staged_manifest() {
        fn block_hex(slot: u32, prefix: usize, len: usize) -> String {
            let mut bytes = vec![0u8; len];
            bytes[prefix..prefix + 4].copy_from_slice(&slot.to_le_bytes());
            hex::encode(&bytes)
        }
        let checkpoint = crate::snapshot::encode(7, b"checkpoint");
        let mut manifest =
            MigrationManifest::new(b"log", [7u8; 32], &checkpoint, 7, ImportSummary::default());
        // No source block: no window.
        assert!(manifest_pause_window_us(&manifest).is_err());
        manifest.source_block = Some(block_hex(1_000, 0, 120));
        // No post-H headers: the pause head must sit strictly past H.
        manifest.halt_post_blocks = Some(vec![]);
        assert!(manifest_pause_window_us(&manifest).is_err());
        // P's time comes from the last staged header, past H's 64-byte prefix.
        manifest.halt_post_blocks =
            Some(vec![block_hex(1_004, 64, 128), block_hex(1_006, 64, 128)]);
        assert_eq!(
            manifest_pause_window_us(&manifest).unwrap(),
            (
                antelope_slot_to_unix_micros(1_000),
                antelope_slot_to_unix_micros(1_006)
            )
        );
    }

    #[test]
    fn antelope_slots_convert_to_deferred_time() {
        // Slot 0 is the Antelope epoch: 2000-01-01T00:00:00Z in Unix micros.
        assert_eq!(antelope_slot_to_unix_micros(0), 946_684_800_000_000);
        // One slot is half a second.
        assert_eq!(
            antelope_slot_to_unix_micros(2) - antelope_slot_to_unix_micros(0),
            1_000_000
        );
        // Monotonic across the full u32 range: saturates, never wraps.
        assert!(antelope_slot_to_unix_micros(u32::MAX) > antelope_slot_to_unix_micros(0));
    }

    #[test]
    fn migration_manifest_accepts_pre_deferred_summary() {
        let manifest: MigrationManifest = serde_json::from_str(
            r#"{
                "version": 1,
                "source_state_history_sha256": "00",
                "source_block_id": "00",
                "checkpoint_sha256": "00",
                "checkpoint_revision": 1,
                "import_summary": {
                    "global_properties": 1,
                    "accounts": 3,
                    "account_metadata": 3,
                    "code_rows": 0,
                    "permissions": 9,
                    "permission_links": 0,
                    "resource_limits": 3,
                    "resource_usage": 3,
                    "resource_states": 1,
                    "resource_configs": 1,
                    "contract_tables": 0,
                    "contract_rows": 0,
                    "index64_rows": 0,
                    "index128_rows": 0,
                    "index256_rows": 0,
                    "index_double_rows": 0,
                    "index_long_double_rows": 0
                }
            }"#,
        )
        .unwrap();
        assert_eq!(manifest.import_summary.accounts, 3);
        assert_eq!(manifest.import_summary.deferred_transactions, 0);
        assert_eq!(manifest.import_summary.input_transactions, 0);
    }

    #[test]
    fn migration_manifest_v2_roster_roundtrips_and_parses() {
        let checkpoint = crate::snapshot::encode(7, b"checkpoint");
        let manifest = MigrationManifest::new(
            b"source state history",
            [9; 32],
            &checkpoint,
            7,
            ImportSummary::default(),
        )
        .with_halt_roster(vec![MigrationHaltRosterEntry {
            producer: "prod.a".to_string(),
            key: "EOS5XPRJt1zUiLH98rtDLj9TnPi52DLQ7gTZbkRvBGJXLv6ak6Cdq".to_string(),
            weight: pulsevm_chain_types::HaltWeight::MEMBER,
        }]);
        assert_eq!(manifest.version, MigrationManifest::VERSION_V2);
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: MigrationManifest = serde_json::from_str(&json).unwrap();
        let roster = parsed
            .roster_entries()
            .expect("roster must parse")
            .expect("v2 manifest must carry a roster");
        assert_eq!(roster.len(), 1);
        assert_eq!(roster[0].producer, "prod.a");
        assert_eq!(roster[0].weight, pulsevm_chain_types::HaltWeight::MEMBER);
        assert!(parsed.verify_checkpoint(&checkpoint).is_ok());
    }

    #[test]
    fn migration_manifest_rejects_unsupported_version() {
        let checkpoint = crate::snapshot::encode(7, b"checkpoint");
        let mut manifest = MigrationManifest::new(
            b"source state history",
            [9; 32],
            &checkpoint,
            7,
            ImportSummary::default(),
        );
        manifest.version = 99;
        assert!(manifest.verify_checkpoint(&checkpoint).is_err());
    }

    use std::str::FromStr as _;

    fn pack_producer_info(
        owner: u64,
        key_bytes: &[u8; 33],
        key_type: u64,
        is_active: bool,
        votes: f64,
    ) -> Vec<u8> {
        fn varuint(mut value: u64, out: &mut Vec<u8>) {
            loop {
                let byte = (value & 0x7f) as u8;
                value >>= 7;
                if value == 0 {
                    out.push(byte);
                    return;
                }
                out.push(byte | 0x80);
            }
        }
        let mut row = Vec::new();
        row.extend_from_slice(&owner.to_le_bytes());
        row.extend_from_slice(&votes.to_le_bytes());
        varuint(key_type, &mut row);
        row.extend_from_slice(key_bytes);
        row.push(u8::from(is_active));
        varuint(3, &mut row);
        row.extend_from_slice(b"url");
        row.extend_from_slice(&0u32.to_le_bytes());
        row.extend_from_slice(&0i64.to_le_bytes());
        row.extend_from_slice(&0u16.to_le_bytes());
        // Head-only, exactly the live mainnet shape: XPR producers rows
        // carry no authority tail, so nothing follows the location field.
        row
    }

    fn test_key(seed: &str) -> pulsevm_crypto::k1::K1PublicKey {
        pulsevm_crypto::k1::K1PrivateKey::from_seed_string(seed)
            .expect("deterministic test key")
            .public_key()
    }

    #[test]
    fn migration_state_producer_keys_decodes_producer_info_rows() {
        let key = test_key("state-roster-1");
        let owner = pulsevm_name::Name::from_str("prod.a").unwrap().as_u64();
        let row = pack_producer_info(owner, &key.compressed(), 0, true, 12345.0);
        let (decoded_owner, decoded) =
            decode_producer_info_row(&row).expect("valid row must decode");
        assert_eq!(decoded_owner, owner);
        assert_eq!(decoded.key, key.compressed());
        assert!(decoded.is_active);
    }

    #[test]
    fn migration_state_producer_keys_rejects_bad_rows() {
        let key = test_key("state-roster-1");
        let owner = pulsevm_name::Name::from_str("prod.a").unwrap().as_u64();
        // Non-K1 key type: nothing downstream can sign for this roster
        // entry, so the freeze must refuse it.
        assert!(
            decode_producer_info_row(&pack_producer_info(owner, &key.compressed(), 1, true, 1.0))
                .is_err()
        );
        // Trailing bytes past the head: a future system-contract field
        // addition must fail loudly, never silently decode.
        let mut trailed = pack_producer_info(owner, &key.compressed(), 0, true, 1.0);
        trailed.push(0);
        assert!(decode_producer_info_row(&trailed).is_err());
        // Truncated row.
        let mut short = pack_producer_info(owner, &key.compressed(), 0, true, 1.0);
        short.truncate(short.len() - 2);
        assert!(decode_producer_info_row(&short).is_err());
    }

    fn state_key(key: &[u8; 33]) -> StateProducerKey {
        StateProducerKey {
            key: *key,
            is_active: true,
            total_votes: 0.0,
        }
    }

    #[test]
    fn halt_roster_cross_check_binds_keys_to_checkpoint_state() {
        let key_a = test_key("state-roster-1");
        let key_b = test_key("state-roster-2");
        let owner_a = pulsevm_name::Name::from_str("prod.a").unwrap().as_u64();
        let owner_b = pulsevm_name::Name::from_str("prod.b").unwrap().as_u64();
        let mut state = BTreeMap::new();
        state.insert(owner_a, state_key(&key_a.compressed()));
        state.insert(owner_b, state_key(&key_b.compressed()));
        let roster = vec![
            pulsevm_chain_types::HaltRosterEntry {
                producer: "prod.a".to_string(),
                key: key_a,
                weight: pulsevm_chain_types::HaltWeight(2),
            },
            pulsevm_chain_types::HaltRosterEntry {
                producer: "prod.b".to_string(),
                key: key_b,
                weight: pulsevm_chain_types::HaltWeight(1),
            },
        ];
        assert_eq!(check_halt_roster_against_state(&roster, &state).unwrap(), 2);
        // Swapped key must fail: the roster no longer matches checkpoint state.
        let forged = vec![pulsevm_chain_types::HaltRosterEntry {
            producer: "prod.a".to_string(),
            key: key_b,
            weight: pulsevm_chain_types::HaltWeight(2),
        }];
        assert!(check_halt_roster_against_state(&forged, &state).is_err());
        // Unknown producer must fail.
        let unknown = vec![pulsevm_chain_types::HaltRosterEntry {
            producer: "prod.zz".to_string(),
            key: key_b,
            weight: pulsevm_chain_types::HaltWeight(1),
        }];
        assert!(check_halt_roster_against_state(&unknown, &state).is_err());
    }

    fn declaration_of(
        members: &[(&str, &pulsevm_crypto::k1::K1PublicKey)],
    ) -> pulsevm_chain_types::HaltDeclaration {
        pulsevm_chain_types::HaltDeclaration {
            version: 1,
            source_chain_id: "00".repeat(32),
            last_height: 8,
            validator_set: members
                .iter()
                .map(|(name, key)| pulsevm_chain_types::HaltDeclarationMember {
                    producer: name.to_string(),
                    key: key.to_string(),
                    weight: pulsevm_chain_types::HaltWeight(1),
                })
                .collect(),
            signatures: Vec::new(),
        }
    }

    fn recorded_map(
        members: &[(&str, &pulsevm_crypto::k1::K1PublicKey)],
    ) -> std::collections::BTreeMap<String, pulsevm_crypto::k1::K1PublicKey> {
        members
            .iter()
            .map(|(name, key)| (name.to_string(), **key))
            .collect()
    }

    #[test]
    fn schedule_match_pins_the_declared_set_both_ways() {
        let key_a = test_key("strict-1");
        let key_b = test_key("strict-2");
        // The recorded schedule comes from the snapshot's header state, so
        // the fixtures below stand in for that artifact — never for the
        // producers table, which carries every active row while the
        // schedule names only the committee.
        let schedule = recorded_map(&[("prod.a", &key_a), ("prod.b", &key_b)]);
        // Exact match passes and reports the committee size.
        let declaration = declaration_of(&[("prod.a", &key_a), ("prod.b", &key_b)]);
        assert_eq!(
            check_declaration_matches_recorded_schedule(&declaration, &schedule).unwrap(),
            2
        );
        // A standby subset declaring itself fails: without the reverse
        // direction it would pass with a denominator it chose and boot a
        // minority chain.
        let subset = declaration_of(&[("prod.a", &key_a)]);
        let err = check_declaration_matches_recorded_schedule(&subset, &schedule).unwrap_err();
        assert!(
            err.contains("does not match the recorded schedule"),
            "a standby subset must fail closed, got: {err}"
        );
        // An extra declared member fails the same way.
        let superset =
            declaration_of(&[("prod.a", &key_a), ("prod.b", &key_b), ("prod.zz", &key_b)]);
        assert!(check_declaration_matches_recorded_schedule(&superset, &schedule).is_err());
        // Unknown producers fail, not silently skipped.
        let unknown = declaration_of(&[("prod.zz", &key_b)]);
        assert!(check_declaration_matches_recorded_schedule(&unknown, &schedule).is_err());
    }

    fn memo_manifest(names: &[String], created_slot: u32) -> MigrationManifest {
        let mut manifest = MigrationManifest::new(
            b"memo test",
            [9u8; 32],
            b"checkpoint",
            1,
            Default::default(),
        );
        manifest.halt_declaration = Some(pulsevm_chain_types::HaltDeclaration {
            version: 1,
            source_chain_id: "00".repeat(32),
            last_height: 8,
            validator_set: Vec::new(),
            signatures: Vec::new(),
        });
        manifest.halt_memo_accounts = Some(
            names
                .iter()
                .map(|name| MigrationMemoAccount {
                    name: name.clone(),
                    created_slot,
                })
                .collect(),
        );
        // The manifest declaration is a placeholder the memo check does not
        // parse: only the recorded names and the expected digest matter.
        manifest
    }

    fn memo_names_for(digest_hex: &str) -> Vec<String> {
        let letters: String = digest_hex
            .bytes()
            .map(|b| {
                let nibble = if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
                (b'a' + nibble) as char
            })
            .collect();
        letters
            .chars()
            .collect::<Vec<_>>()
            .chunks(10)
            .map(|chunk| format!("ha{}", chunk.iter().collect::<String>()))
            .collect()
    }

    #[test]
    fn memo_proof_decodes_names_and_requires_pre_h_creation() {
        let digest = [0xABu8; 32];
        let digest_hex = hex::encode(digest);
        let names = memo_names_for(&digest_hex);
        assert_eq!(names.len(), 7);
        // Valid proof: names decode to the digest, all created before H.
        let manifest = memo_manifest(&names, 50);
        assert_eq!(
            verify_migration_memo_accounts(&manifest, &digest, 100).unwrap(),
            7
        );
        // Wrong digest fails: the names commit to exactly one digest.
        let other = [0xCDu8; 32];
        let err = verify_migration_memo_accounts(&manifest, &other, 100).unwrap_err();
        assert!(err.contains("do not decode"), "{err}");
        // Created at or after H fails: the declaration must land before H.
        for slot in [100, 101] {
            let late = memo_manifest(&names, slot);
            let err = verify_migration_memo_accounts(&late, &digest, 100).unwrap_err();
            assert!(err.contains("must land before H"), "{err}");
        }
        // Malformed names fail.
        let mut broken = names.clone();
        broken[0] = "xyz".to_string();
        let broken_manifest = memo_manifest(&broken, 50);
        let err = verify_migration_memo_accounts(&broken_manifest, &digest, 100).unwrap_err();
        assert!(
            err.contains("does not carry the declaration digest"),
            "{err}"
        );
        // No memo record: the contract vehicle and legacy paths skip.
        let mut bare = memo_manifest(&names, 50);
        bare.halt_memo_accounts = None;
        assert_eq!(
            verify_migration_memo_accounts(&bare, &digest, 100).unwrap(),
            0
        );
        // An empty record fails closed instead of vacuously passing.
        let mut empty = memo_manifest(&names, 50);
        empty.halt_memo_accounts = Some(Vec::new());
        assert!(verify_migration_memo_accounts(&empty, &digest, 100).is_err());
    }

    #[test]
    fn schedule_match_rejects_key_drift() {
        let key_a = test_key("strict-1");
        let key_b = test_key("strict-2");
        let schedule = recorded_map(&[("prod.a", &key_a), ("prod.b", &key_b)]);
        // A schedule-key rotation on one member fails: the frozen set no
        // longer names the keys that produce.
        let drifted = declaration_of(&[("prod.a", &key_b), ("prod.b", &key_b)]);
        assert!(check_declaration_matches_recorded_schedule(&drifted, &schedule).is_err());
    }

    #[test]
    fn transport_roster_rejects_non_unit_weights() {
        // An exporter cannot move the denominator: transported weights must
        // be exactly 1, however large the on-chain votes behind them are.
        let (mut manifest, _, _) = halt_test_manifest();
        let key = test_key("weight-1");
        manifest = manifest.with_halt_roster(vec![MigrationHaltRosterEntry {
            producer: "prod.a".to_string(),
            key: key.to_string(),
            weight: pulsevm_chain_types::HaltWeight(50),
        }]);
        assert!(manifest.roster_entries().is_err());
    }

    #[test]
    fn migration_state_producer_keys_derive_from_hydrated_state() {
        let system = pulsevm_name::Name::from_str("eosio").unwrap().as_u64();
        let producers = pulsevm_name::Name::from_str("producers").unwrap().as_u64();
        let payer = 55u64;
        let key = test_key("state-roster-1");
        let owner = pulsevm_name::Name::from_str("prod.a").unwrap().as_u64();
        let mut table_row = vec![0];
        for value in [system, system, producers, payer] {
            table_row.extend_from_slice(&value.to_le_bytes());
        }
        let mut kv_row = secondary_prefix(system, system, producers, owner, payer);
        bytes(
            &mut kv_row,
            &pack_producer_info(owner, &key.compressed(), 0, true, 12345.0),
        );
        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [0; 32],
            deltas: vec![
                delta("contract_table", table_row),
                delta("contract_row", kv_row),
            ],
        };
        let dir = TempDir::new().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();
        hydrate_full_state(&mut db, &entry).unwrap();
        let map = migration_state_producer_keys(&db).expect("derivation must succeed");
        assert_eq!(map.len(), 1);
        assert_eq!(map[&owner].key, key.compressed());
        // The template carries the same key with the on-chain vote weight.
        let template = migration_halt_roster_template(&db).unwrap();
        assert_eq!(template.len(), 1);
        assert_eq!(template[0].producer, "prod.a");
        assert_eq!(template[0].weight, pulsevm_chain_types::HaltWeight::MEMBER);
        let parsed = pulsevm_chain_types::HaltRosterEntry {
            producer: template[0].producer.clone(),
            key: pulsevm_crypto::k1::K1PublicKey::from_string(&template[0].key).unwrap(),
            weight: template[0].weight,
        };
        assert_eq!(parsed.key.compressed(), key.compressed());
        let roster = vec![pulsevm_chain_types::HaltRosterEntry {
            producer: "prod.a".to_string(),
            key,
            weight: pulsevm_chain_types::HaltWeight::MEMBER,
        }];
        assert_eq!(check_halt_roster_against_state(&roster, &map).unwrap(), 1);
    }

    #[test]
    fn halt_roster_template_weighs_every_member_one() {
        // `total_votes` is deliberately ignored: mainnet magnitudes (top
        // producer ~5.25e21) would otherwise drag vote-weight quorum math
        // back in. Every templated member weighs exactly 1.
        let system = pulsevm_name::Name::from_str("eosio").unwrap().as_u64();
        let producers = pulsevm_name::Name::from_str("producers").unwrap().as_u64();
        let payer = 55u64;
        let big = test_key("magnitude-big");
        let small = test_key("magnitude-small");
        let owner_big = pulsevm_name::Name::from_str("prod.big").unwrap().as_u64();
        let owner_small = pulsevm_name::Name::from_str("prod.small").unwrap().as_u64();
        let votes_big = 5.251494364735212e21_f64;
        let votes_small = 1.5792002538645e20_f64;
        let mut table_row = vec![0];
        for value in [system, system, producers, payer] {
            table_row.extend_from_slice(&value.to_le_bytes());
        }
        let mut kv_big = secondary_prefix(system, system, producers, owner_big, payer);
        bytes(
            &mut kv_big,
            &pack_producer_info(owner_big, &big.compressed(), 0, true, votes_big),
        );
        let mut kv_small = secondary_prefix(system, system, producers, owner_small, payer);
        bytes(
            &mut kv_small,
            &pack_producer_info(owner_small, &small.compressed(), 0, true, votes_small),
        );
        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [0; 32],
            deltas: vec![
                delta("contract_table", table_row),
                delta("contract_row", kv_big),
                delta("contract_row", kv_small),
            ],
        };
        let dir = TempDir::new().unwrap();
        let mut db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();
        hydrate_full_state(&mut db, &entry).unwrap();
        let template = migration_halt_roster_template(&db).unwrap();
        assert_eq!(template.len(), 2);
        for entry in &template {
            assert_eq!(entry.weight, pulsevm_chain_types::HaltWeight::MEMBER);
        }
    }

    #[test]
    fn independent_conversions_of_one_export_give_identical_checkpoints() {
        // Every BP signs its own checkpoint, so two independent conversions
        // of the same Leap export must give byte-identical migration.snapshot
        // files. Convert the same entry twice into two fresh databases and
        // compare the checkpoint bytes exactly.
        fn convert(entry: &StateHistoryEntry) -> Vec<u8> {
            let dir = TempDir::new().unwrap();
            let mut db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();
            hydrate_full_state(&mut db, entry).unwrap();
            db.set_revision(7).unwrap();
            db.snapshot_bytes().unwrap()
        }
        let system = pulsevm_name::Name::from_str("eosio").unwrap().as_u64();
        let producers = pulsevm_name::Name::from_str("producers").unwrap().as_u64();
        let payer = 55u64;
        let mut table_row = vec![0];
        for value in [system, system, producers, payer] {
            table_row.extend_from_slice(&value.to_le_bytes());
        }
        let mut deltas = vec![delta("contract_table", table_row)];
        for (index, seed) in ["check-a", "check-b", "check-c"].iter().enumerate() {
            let key = test_key(seed);
            let owner = pulsevm_name::Name::from_str(match index {
                0 => "prod.a",
                1 => "prod.b",
                _ => "prod.c",
            })
            .unwrap()
            .as_u64();
            let mut kv_row = secondary_prefix(system, system, producers, owner, payer);
            bytes(
                &mut kv_row,
                &pack_producer_info(owner, &key.compressed(), 0, true, 100.0 + index as f64),
            );
            deltas.push(delta("contract_row", kv_row));
        }
        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [0; 32],
            deltas,
        };
        let first = convert(&entry);
        let second = convert(&entry);
        assert!(!first.is_empty());
        assert_eq!(
            first, second,
            "independent conversions of one export must be byte-identical"
        );
    }

    #[test]
    fn real_export_path_gives_identical_per_bp_checkpoints() {
        // Every BP converts the same Leap export and signs its own
        // checkpoint, so two independent conversions must give
        // byte-identical snapshots through the REAL importer path — the
        // sidecar, protocol state, and resource tables included, not just
        // the producer rows. Convert twice into fresh databases and compare
        // the checkpoint bytes (and their sha, the per-BP signing input)
        // exactly.
        fn convert(entry: &StateHistoryEntry, sidecar: &DeferredTransactionSidecar) -> Vec<u8> {
            let dir = TempDir::new().unwrap();
            let mut db = Database::new(dir.path().to_str().unwrap(), 64 * 1024 * 1024).unwrap();
            hydrate_full_state_with_deferred_transactions(&mut db, entry, Some(sidecar)).unwrap();
            db.set_revision(7).unwrap();
            db.snapshot_bytes().unwrap()
        }
        let system = pulsevm_name::Name::from_str("eosio").unwrap().as_u64();
        let producers = pulsevm_name::Name::from_str("producers").unwrap().as_u64();
        let payer = 55u64;
        let mut table_row = vec![0];
        for value in [system, system, producers, payer] {
            table_row.extend_from_slice(&value.to_le_bytes());
        }
        let mut deltas = vec![delta("contract_table", table_row)];
        for (index, seed) in ["check-a", "check-b", "check-c"].iter().enumerate() {
            let key = test_key(seed);
            let owner = pulsevm_name::Name::from_str(match index {
                0 => "prod.a",
                1 => "prod.b",
                _ => "prod.c",
            })
            .unwrap()
            .as_u64();
            let mut kv_row = secondary_prefix(system, system, producers, owner, payer);
            bytes(
                &mut kv_row,
                &pack_producer_info(owner, &key.compressed(), 0, true, 100.0 + index as f64),
            );
            deltas.push(delta("contract_row", kv_row));
        }
        // Chain config exactly as Leap 5 ships it (modern layout).
        deltas.push(delta(
            "global_property",
            hex::decode("01000000000000010000100000000000e8030000000008000c000000f40100001400000064000000400d0300e8030000f049020064000000100e00005802000080533b000010000004000600000100009371fb05f023fcc78b23923d70bdfe6642cdf1956d120045bcd1371e05c961a90000040000000400000020000000000100002000000004000000200000000040010000400110020000fb000000").unwrap(),
        ));
        // Two protocol features, activated in block order.
        let mut protocol_row = vec![0, 2];
        for (digest, block) in [([0xF0u8; 32], 100u32), ([0xF1u8; 32], 200u32)] {
            protocol_row.push(0);
            protocol_row.extend_from_slice(&digest);
            protocol_row.extend_from_slice(&block.to_le_bytes());
        }
        deltas.push(delta("protocol_state", protocol_row));
        // Resource limits and usage for the deferred payer.
        let account = 11u64;
        let mut limits_row = vec![0];
        limits_row.extend_from_slice(&account.to_le_bytes());
        for weight in [-1i64, 2, 4096] {
            limits_row.extend_from_slice(&weight.to_le_bytes());
        }
        deltas.push(delta("resource_limits", limits_row));
        let mut usage_row = vec![0];
        usage_row.extend_from_slice(&account.to_le_bytes());
        for _ in 0..2 {
            usage_row.push(0);
            usage_row.extend_from_slice(&1u32.to_le_bytes());
            usage_row.extend_from_slice(&2u64.to_le_bytes());
            usage_row.extend_from_slice(&3u64.to_le_bytes());
        }
        usage_row.extend_from_slice(&4u64.to_le_bytes());
        deltas.push(delta("resource_usage", usage_row));
        // One account with metadata, code, and an owner permission, exactly
        // the rows the sidecar must cover one-for-one.
        let code_hash = [0xC0u8; 32];
        let mut account_row = vec![0];
        account_row.extend_from_slice(&account.to_le_bytes());
        account_row.extend_from_slice(&7u32.to_le_bytes());
        bytes(&mut account_row, &[]);
        deltas.push(delta("account", account_row));
        let mut metadata_row = vec![0];
        metadata_row.extend_from_slice(&account.to_le_bytes());
        metadata_row.push(0);
        metadata_row.extend_from_slice(&0i64.to_le_bytes());
        metadata_row.push(1);
        metadata_row.extend_from_slice(&[0, 0]);
        metadata_row.extend_from_slice(&code_hash);
        deltas.push(delta("account_metadata", metadata_row));
        let mut code_row = vec![0, 0, 0];
        code_row.extend_from_slice(&code_hash);
        bytes(&mut code_row, &[0, 97, 115, 109]);
        deltas.push(delta("code", code_row));
        let mut permission_row = vec![0];
        permission_row.extend_from_slice(&account.to_le_bytes());
        permission_row.extend_from_slice(&111u64.to_le_bytes());
        permission_row.extend_from_slice(&0u64.to_le_bytes());
        permission_row.extend_from_slice(&0i64.to_le_bytes());
        permission_row.extend_from_slice(&0u32.to_le_bytes());
        permission_row.extend_from_slice(&[0, 0, 0]);
        deltas.push(delta("permission", permission_row));
        // One deferred transaction: the SHiP row carries identity and
        // payload, the sidecar the three scheduler timestamps.
        let trx_id = [0xD0u8; 32];
        let packed_trx = vec![0xde, 0xad, 0xbe, 0xef];
        let published = 1_700_000_000_000_000i64;
        let mut generated_row = vec![0];
        generated_row.extend_from_slice(&account.to_le_bytes());
        generated_row.extend_from_slice(&7u64.to_le_bytes());
        generated_row.extend_from_slice(&0u64.to_le_bytes());
        generated_row.extend_from_slice(&account.to_le_bytes());
        generated_row.extend_from_slice(&trx_id);
        bytes(&mut generated_row, &packed_trx);
        deltas.push(delta("generated_transaction", generated_row));
        let entry = StateHistoryEntry {
            magic: 0,
            block_id: [7; 32],
            deltas,
        };
        let sidecar = DeferredTransactionSidecar {
            version: DeferredTransactionSidecar::VERSION,
            source_block_id: hex::encode(entry.block_id),
            source_chain_id: None,
            account_metadata: vec![AccountMetadataSidecarRow {
                name: account,
                recv_sequence: 7,
                auth_sequence: 8,
                code_sequence: 9,
                abi_sequence: 10,
            }],
            code: vec![CodeSidecarRow {
                code_hash: hex::encode(code_hash),
                vm_type: 0,
                vm_version: 0,
                code_ref_count: 1,
                first_block_used: 399_000_123,
            }],
            permissions: vec![PermissionSidecarRow {
                owner: account,
                name: 111,
                last_used: 123_456,
            }],
            global_action_sequence: 987_654_321,
            input_transactions: vec![],
            transactions: vec![DeferredTransactionSidecarRow {
                sender: account,
                sender_id: "7".to_string(),
                payer: account,
                trx_id: hex::encode(trx_id),
                delay_until: published + 3_600_000_000,
                expiration: published + 7_200_000_000,
                published,
                packed_trx: hex::encode(&packed_trx),
            }],
        };
        let first = convert(&entry, &sidecar);
        let second = convert(&entry, &sidecar);
        assert!(!first.is_empty());
        assert_eq!(
            first, second,
            "independent conversions of one real export must be byte-identical"
        );
        // The per-BP signing input is the checkpoint sha: equal bytes hash
        // equal, so every BP signs the same digest.
        assert_eq!(
            pulsevm_crypto::Digest::hash(&first),
            pulsevm_crypto::Digest::hash(&second)
        );
    }

    fn halt_test_manifest() -> (MigrationManifest, [u8; 32], [u8; 32]) {
        let checkpoint = crate::snapshot::encode(7, b"checkpoint");
        // Height-consistent H id: the post-chain walk derives each height
        // as parent-num + 1, so the fixture anchor must embed H itself.
        let mut hid = [9u8; 32];
        hid[0..4].copy_from_slice(&7u32.to_be_bytes());
        let manifest = MigrationManifest::new(
            b"source state history",
            hid,
            &checkpoint,
            7,
            ImportSummary::default(),
        );
        let hash: [u8; 32] = hex::decode(&manifest.checkpoint_sha256)
            .unwrap()
            .try_into()
            .unwrap();
        (manifest, hid, hash)
    }

    /// Pack one synthetic post-H signed block: `pulsevm_core::block` wire
    /// layout, signed by `signing` over the header digest. Returns the hex
    /// plus the block id the walk recomputes (sha256 header, number
    /// overwritten big-endian). Mirrors the layout comment on
    /// `read_post_block`; the handover rehearsal covers the same walk
    /// against real Leap blocks.
    #[allow(clippy::too_many_arguments)]
    /// Fixed schedule hash the pair fixtures stage: the gate binds the
    /// exact (root, hash) pair through the producer signature, so any
    /// consistent value exercises the real check.
    const FIXTURE_SCHEDULE_HASH: [u8; 32] = [0x5E; 32];

    // Ten arguments because the fixture packs every byte the gate walks:
    // header shape knobs plus the recorded root and schedule hash.
    #[allow(clippy::too_many_arguments)]
    fn pack_post_block(
        previous: &[u8; 32],
        producer: u64,
        signing: &pulsevm_crypto::k1::K1PrivateKey,
        schedule_version: u32,
        tx_count: u32,
        transaction_mroot: [u8; 32],
        schedule_change: bool,
        trailer: &[u8],
        root: [u8; 32],
        schedule_hash: [u8; 32],
        // Post-H entries carry the two zero counts the gate requires; the
        // H entry omits them (H may carry traffic the entry does not stage).
        with_counts: bool,
    ) -> (String, [u8; 32]) {
        fn varuint(mut value: u32, out: &mut Vec<u8>) {
            loop {
                let byte = (value & 0x7f) as u8;
                value >>= 7;
                if value == 0 {
                    out.push(byte);
                    return;
                }
                out.push(byte | 0x80);
            }
        }
        let mut header = Vec::new();
        header.extend_from_slice(&0x01020304u32.to_le_bytes());
        header.extend_from_slice(&producer.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(previous);
        header.extend_from_slice(&transaction_mroot);
        header.extend_from_slice(&[0u8; 32]);
        header.extend_from_slice(&schedule_version.to_le_bytes());
        header.push(u8::from(schedule_change));
        header.push(0); // no header extensions
        let header_digest = pulsevm_crypto::Digest::hash(&header).0;
        // Leap's producer signature digest: sha256(sha256(header ||
        // blockroot) || pending-schedule-hash). The recorded proof leads
        // with root and schedule hash so the gate recomputes this exactly.
        let mut digest_and_root = Vec::with_capacity(64);
        digest_and_root.extend_from_slice(&header_digest);
        digest_and_root.extend_from_slice(&root);
        let bound = pulsevm_crypto::Digest::hash(&digest_and_root).0;
        let mut bound_and_schedule = Vec::with_capacity(64);
        bound_and_schedule.extend_from_slice(&bound);
        bound_and_schedule.extend_from_slice(&schedule_hash);
        let digest = pulsevm_crypto::Digest::hash(&bound_and_schedule).0;
        let compact = signing.sign(&digest).compact65();
        let mut packed = Vec::with_capacity(64 + header.len() + 67);
        packed.extend_from_slice(&root);
        packed.extend_from_slice(&schedule_hash);
        packed.extend_from_slice(&header);
        packed.push(0); // K1 tag
        packed.extend_from_slice(&compact);
        if with_counts {
            varuint(tx_count, &mut packed);
            packed.push(0); // no block extensions
        }
        packed.extend_from_slice(trailer);
        let num = u32::from_be_bytes(previous[0..4].try_into().unwrap()) + 1;
        let mut id = header_digest;
        id[0..4].copy_from_slice(&num.to_be_bytes());
        // The entry carries the header-derived block id, which the gate
        // recomputes from the packed header and requires to match exactly.
        packed.extend_from_slice(&id);
        (hex::encode(&packed), id)
    }

    fn halt_v1_commitment(
        signing: &pulsevm_crypto::k1::K1PrivateKey,
        producer: &str,
        height: u32,
        id: &[u8; 32],
    ) -> pulsevm_chain_types::HaltCommitment {
        let digest = pulsevm_chain_types::HaltCommitment::digest(height, id);
        pulsevm_chain_types::HaltCommitment {
            version: pulsevm_chain_types::HaltCommitment::VERSION,
            halt_height: height,
            halt_block_id: hex::encode(id),
            checkpoint_sha256: None,
            producer_keys: vec![signing.public_key().to_string()],
            signatures: vec![pulsevm_chain_types::HaltSignature {
                producer: producer.to_string(),
                key: signing.public_key().to_string(),
                signature: signing.sign(&digest).to_string(),
            }],
        }
    }

    #[test]
    fn verify_migration_halt_rejects_rosterless_single_key() {
        // One valid signature with no roster proves nothing about the
        // schedule: the legacy single-key path is rejected even though the
        // signature itself verifies.
        let (mut manifest, id, checkpoint) = halt_test_manifest();
        let signing = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("dispatch-1").unwrap();
        manifest.halt_commitment = Some(halt_v1_commitment(&signing, "prod.a", 7, &id));
        let error = verify_migration_halt_commitment(&manifest, 7, &id, &checkpoint).unwrap_err();
        assert!(
            error.contains("no roster"),
            "roster-less commitments must fail closed, got: {error}"
        );
    }

    #[test]
    fn verify_migration_halt_accepts_v2_roster_quorum_and_rejects_shortfall() {
        let (manifest, id, checkpoint) = halt_test_manifest();
        let k1 = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("dispatch-1").unwrap();
        let k2 = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("dispatch-2").unwrap();
        let roster = vec![
            MigrationHaltRosterEntry {
                producer: "prod.a".to_string(),
                key: k1.public_key().to_string(),
                weight: pulsevm_chain_types::HaltWeight::MEMBER,
            },
            MigrationHaltRosterEntry {
                producer: "prod.b".to_string(),
                key: k2.public_key().to_string(),
                weight: pulsevm_chain_types::HaltWeight::MEMBER,
            },
        ];
        let sign = |key: &pulsevm_crypto::k1::K1PrivateKey, producer: &str| {
            let digest = pulsevm_chain_types::HaltCommitment::digest_v2(7, &id, &checkpoint);
            pulsevm_chain_types::HaltSignature {
                producer: producer.to_string(),
                key: key.public_key().to_string(),
                signature: key.sign(&digest).to_string(),
            }
        };
        let mut full = manifest.clone().with_halt_roster(roster);
        let checkpoint_hex = full.checkpoint_sha256.clone();
        full.halt_commitment = Some(pulsevm_chain_types::HaltCommitment {
            version: pulsevm_chain_types::HaltCommitment::VERSION_V2,
            halt_height: 7,
            halt_block_id: hex::encode(id),
            checkpoint_sha256: Some(checkpoint_hex),
            producer_keys: vec![],
            signatures: vec![sign(&k1, "prod.a"), sign(&k2, "prod.b")],
        });
        verify_migration_halt_commitment(&full, 7, &id, &checkpoint).unwrap();
        // Only prod.b (1 of 2) signs: below the two-thirds quorum.
        let mut short = full.clone();
        short.halt_commitment.as_mut().unwrap().signatures = vec![sign(&k2, "prod.b")];
        assert!(verify_migration_halt_commitment(&short, 7, &id, &checkpoint).is_err());
    }

    #[test]
    fn verify_migration_halt_rejects_bad_version_and_bad_checkpoint() {
        let (mut manifest, id, checkpoint) = halt_test_manifest();
        let signing = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("dispatch-1").unwrap();
        let mut commitment = halt_v1_commitment(&signing, "prod.a", 7, &id);
        commitment.version = 7;
        manifest.halt_commitment = Some(commitment);
        assert!(verify_migration_halt_commitment(&manifest, 7, &id, &checkpoint).is_err());
        let (mut manifest, id, _) = halt_test_manifest();
        let mut commitment = halt_v1_commitment(&signing, "prod.a", 7, &id);
        commitment.version = pulsevm_chain_types::HaltCommitment::VERSION_V2;
        manifest.halt_commitment = Some(commitment);
        assert!(verify_migration_halt_commitment(&manifest, 7, &id, &[8; 32]).is_err());
    }

    /// H's schedule version in the pair fixture: every vote and the
    /// attested version pin to exactly this.
    const TEST_SCHEDULE_VERSION: u32 = 42;
    /// The platform (MetalGo blockchain) id the pair-fixture confirmation
    /// binds: the restore always configures one, so fixtures carry one.
    const TEST_PLATFORM_ID: [u8; 32] = [0x51; 32];

    fn halt_test_pair() -> (MigrationManifest, [u8; 32], [u8; 32], [u8; 32]) {
        let (mut manifest, _synthetic_id, checkpoint) = halt_test_manifest();
        let k1 = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("pair-1").unwrap();
        let k2 = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("pair-2").unwrap();
        let prod_a = pulsevm_name::Name::from_str("prod.a").unwrap().as_u64();
        let prod_b = pulsevm_name::Name::from_str("prod.b").unwrap().as_u64();
        let sched = FIXTURE_SCHEDULE_HASH;
        // The cutover block itself is a gate entry: its header derives the
        // H id, so the window opens on a signature-checked H. The template
        // and the posts below all bind this derived id.
        let mut parent6 = [6u8; 32];
        parent6[0..4].copy_from_slice(&6u32.to_be_bytes());
        let (h_block, hid) = pack_post_block(
            &parent6,
            prod_a,
            &k1,
            TEST_SCHEDULE_VERSION,
            0,
            [0u8; 32],
            false,
            &[],
            [7u8; 32],
            sched,
            false,
        );
        manifest.source_block_id = hex::encode(hid);
        let mut members = vec![
            pulsevm_chain_types::HaltDeclarationMember {
                producer: "prod.a".to_string(),
                key: k1.public_key().to_string(),
                weight: pulsevm_chain_types::HaltWeight::MEMBER,
            },
            pulsevm_chain_types::HaltDeclarationMember {
                producer: "prod.b".to_string(),
                key: k2.public_key().to_string(),
                weight: pulsevm_chain_types::HaltWeight::MEMBER,
            },
        ];
        pulsevm_chain_types::HaltDeclaration::sort_members(&mut members);
        let unsigned = pulsevm_chain_types::HaltDeclaration {
            version: pulsevm_chain_types::HaltDeclaration::VERSION,
            source_chain_id: "41".repeat(32),
            last_height: 7,
            validator_set: members,
            signatures: Vec::new(),
        };
        let decl_digest = unsigned.digest().unwrap();
        let sign_decl = |key: &pulsevm_crypto::k1::K1PrivateKey, producer: &str| {
            pulsevm_chain_types::HaltSignature {
                producer: producer.to_string(),
                key: key.public_key().to_string(),
                signature: key.sign(&decl_digest).to_string(),
            }
        };
        let declaration = pulsevm_chain_types::HaltDeclaration {
            signatures: vec![sign_decl(&k1, "prod.a"), sign_decl(&k2, "prod.b")],
            ..unsigned
        };
        let new_chain = [0x31; 32];
        let template = pulsevm_chain_types::HaltConfirmation {
            version: pulsevm_chain_types::HaltConfirmation::VERSION,
            declaration_digest: hex::encode(declaration.digest().unwrap()),
            halt_height: 7,
            // The fixture stages two post-H emptiness headers (blocks 8 and
            // 9 below), so the attested pause head is exactly 9. The H id
            // is derived from the staged H entry above, never synthetic.
            pause_height: 9,
            halt_block_id: hex::encode(hid),
            checkpoint_sha256: hex::encode(checkpoint),
            new_chain_id: hex::encode(new_chain),
            platform_chain_id: hex::encode(TEST_PLATFORM_ID),
            signatures: Vec::new(),
        };
        let conf_digest = template.digest().unwrap();
        let sign_conf = |key: &pulsevm_crypto::k1::K1PrivateKey, producer: &str| {
            pulsevm_chain_types::HaltSignature {
                producer: producer.to_string(),
                key: key.public_key().to_string(),
                signature: key.sign(&conf_digest).to_string(),
            }
        };
        let mut manifest = manifest.with_halt_roster(vec![
            MigrationHaltRosterEntry {
                producer: "prod.a".to_string(),
                key: k1.public_key().to_string(),
                weight: pulsevm_chain_types::HaltWeight::MEMBER,
            },
            MigrationHaltRosterEntry {
                producer: "prod.b".to_string(),
                key: k2.public_key().to_string(),
                weight: pulsevm_chain_types::HaltWeight::MEMBER,
            },
        ]);
        manifest.halt_declaration = Some(declaration.clone());
        manifest.halt_confirmation = Some(pulsevm_chain_types::HaltConfirmation {
            signatures: vec![sign_conf(&k1, "prod.a"), sign_conf(&k2, "prod.b")],
            ..template
        });
        // The pair always carries the on-chain ceremony: both votes land
        // before H (blocks 5 and 6), the singleton is finalized at 6, and
        // the captured tally equals the recomputed signer count (1 + 1).
        // Weights are 1 and 1: both votes clear the strict count quorum at
        // 2 of 2.
        let vote = |producer: &str, key: &str, signature: &str, block: u32| {
            pulsevm_chain_types::HaltContractVote {
                producer: producer.to_string(),
                block,
                schedule_version: TEST_SCHEDULE_VERSION,
                key: key.to_string(),
                signature: signature.to_string(),
            }
        };
        let key_a = declaration.validator_set[0].key.clone();
        let key_b = declaration.validator_set[1].key.clone();
        let sig_a = declaration.signatures[0].signature.clone();
        let sig_b = declaration.signatures[1].signature.clone();
        manifest.halt_contract_ceremony = Some(pulsevm_chain_types::HaltContractCeremony {
            contract: "cutover".to_string(),
            declaration_digest: hex::encode(decl_digest),
            total_weight: pulsevm_chain_types::HaltWeight(2),
            voted_weight: pulsevm_chain_types::HaltWeight(2),
            finalized: true,
            finalized_block: 6,
            init_time: 0,
            votes: vec![
                vote("prod.a", &key_a, &sig_a, 5),
                vote("prod.b", &key_b, &sig_b, 6),
            ],
        });
        manifest.halt_schedule_version = Some(TEST_SCHEDULE_VERSION);
        // The export attests no proposed schedule in the checkpoint: the
        // restore fails closed on anything else.
        manifest.halt_proposed_schedule = Some(false);
        // The recorded schedule is the declared set: the pair fixture's
        // empty window (blocks 8 and 9, signed by the schedule keys) links
        // from H and proves nothing landed after the freeze.
        manifest.halt_schedule = Some(vec![
            MigrationHaltRosterEntry {
                producer: "prod.a".to_string(),
                key: k1.public_key().to_string(),
                weight: pulsevm_chain_types::HaltWeight::MEMBER,
            },
            MigrationHaltRosterEntry {
                producer: "prod.b".to_string(),
                key: k2.public_key().to_string(),
                weight: pulsevm_chain_types::HaltWeight::MEMBER,
            },
        ]);
        let (post8, id8) = pack_post_block(
            &hid,
            prod_a,
            &k1,
            TEST_SCHEDULE_VERSION,
            0,
            [0u8; 32],
            false,
            &[],
            [8u8; 32],
            sched,
            true,
        );
        let (post9, _) = pack_post_block(
            &id8,
            prod_b,
            &k2,
            TEST_SCHEDULE_VERSION,
            0,
            [0u8; 32],
            false,
            &[],
            [9u8; 32],
            sched,
            true,
        );
        manifest.halt_post_blocks = Some(vec![post8, post9]);
        manifest.halt_h_block = Some(h_block);
        (manifest, hid, checkpoint, new_chain)
    }

    #[test]
    fn verify_migration_halt_pair_accepts_and_binds_every_link() {
        let (manifest, id, checkpoint, new_chain) = halt_test_pair();
        let roster = verify_migration_halt_pair(
            &manifest,
            7,
            &id,
            &checkpoint,
            &new_chain,
            TEST_SCHEDULE_VERSION,
            Some(&TEST_PLATFORM_ID),
        )
        .expect("cutover pair must verify");
        assert_eq!(roster.len(), 2);
    }

    #[test]
    fn pair_rejects_an_unattested_or_substituted_cutover_block() {
        let (manifest, id, checkpoint, new_chain) = halt_test_pair();
        let run = |manifest: &MigrationManifest| {
            verify_migration_halt_pair(
                manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID),
            )
        };
        // No H entry: the window cannot open on an unattested H.
        let mut bare = manifest.clone();
        bare.halt_h_block = None;
        let err = run(&bare).unwrap_err();
        assert!(
            err.contains("cutover-block evidence") || err.contains("unattested H"),
            "a pair without an H entry must fail closed, got: {err}"
        );
        // Substituted H: the entry's derived id no longer matches the
        // terminal block the confirmation binds.
        let mut swapped = manifest.clone();
        let mut raw = hex::decode(swapped.halt_h_block.clone().unwrap()).unwrap();
        let id_off = raw.len() - 32;
        raw[id_off + 5] ^= 1;
        swapped.halt_h_block = Some(hex::encode(&raw));
        let err = run(&swapped).unwrap_err();
        assert!(
            err.contains("cutover block"),
            "a substituted H entry must fail closed, got: {err}"
        );
    }

    #[test]
    fn post_chain_covers_exactly_the_attested_pause_head() {
        let (manifest, id, checkpoint, new_chain) = halt_test_pair();
        let run = |manifest: &MigrationManifest| {
            verify_migration_halt_pair(
                manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID),
            )
        };
        // The fixture attests pause head 9 with two staged headers (8, 9):
        // a proof that stops at 8 leaves block 9 unproven and fails closed.
        let mut short = manifest.clone();
        short.halt_post_blocks = Some(short.halt_post_blocks.unwrap()[..1].to_vec());
        let err = run(&short).unwrap_err();
        assert!(
            err.contains("pause head 9"),
            "a proof short of the attested pause head must fail, got: {err}"
        );
        // A proof that runs to block 10 stages a header past what the
        // quorum observed: the extra header fails closed too.
        let k1 = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("pair-1").unwrap();
        let k2 = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("pair-2").unwrap();
        let prod_a = pulsevm_name::Name::from_str("prod.a").unwrap().as_u64();
        let prod_b = pulsevm_name::Name::from_str("prod.b").unwrap().as_u64();
        let sched = FIXTURE_SCHEDULE_HASH;
        let (_, id8) = pack_post_block(
            &id,
            prod_a,
            &k1,
            TEST_SCHEDULE_VERSION,
            0,
            [0u8; 32],
            false,
            &[],
            [8u8; 32],
            sched,
            true,
        );
        let (_, id9) = pack_post_block(
            &id8,
            prod_b,
            &k2,
            TEST_SCHEDULE_VERSION,
            0,
            [0u8; 32],
            false,
            &[],
            [9u8; 32],
            sched,
            true,
        );
        let (post10, _) = pack_post_block(
            &id9,
            prod_a,
            &k1,
            TEST_SCHEDULE_VERSION,
            0,
            [0u8; 32],
            false,
            &[],
            [10u8; 32],
            sched,
            true,
        );
        let mut long = manifest.clone();
        long.halt_post_blocks.as_mut().unwrap().push(post10);
        let err = run(&long).unwrap_err();
        assert!(
            err.contains("pause head 9"),
            "a proof past the attested pause head must fail, got: {err}"
        );
        // A pause that lands exactly on H must fail closed: zero staged
        // headers cannot distinguish a frozen network from a bare anchor,
        // so the quorum must attest a head strictly past H (the pause
        // head is re-signed over 7 here, and the empty window is rejected
        // even with a matching quorum).
        let declaration = manifest.halt_declaration.clone().unwrap();
        let decl_digest = declaration.digest().unwrap();
        let template = pulsevm_chain_types::HaltConfirmation {
            version: pulsevm_chain_types::HaltConfirmation::VERSION,
            declaration_digest: hex::encode(decl_digest),
            halt_height: 7,
            pause_height: 7,
            halt_block_id: hex::encode(id),
            checkpoint_sha256: hex::encode(checkpoint),
            new_chain_id: hex::encode(new_chain),
            platform_chain_id: hex::encode(TEST_PLATFORM_ID),
            signatures: Vec::new(),
        };
        let conf_digest = template.digest().unwrap();
        let mut landed = manifest.clone();
        landed.halt_confirmation = Some(pulsevm_chain_types::HaltConfirmation {
            signatures: [(&k1, "prod.a"), (&k2, "prod.b")]
                .iter()
                .map(|(key, producer)| pulsevm_chain_types::HaltSignature {
                    producer: producer.to_string(),
                    key: key.public_key().to_string(),
                    signature: key.sign(&conf_digest).to_string(),
                })
                .collect(),
            ..template
        });
        landed.halt_post_blocks = Some(Vec::new());
        let err = run(&landed).unwrap_err();
        assert!(
            err.contains("strictly past H") || err.contains("pause head"),
            "a pause exactly on H must fail closed, got: {err}"
        );
    }

    #[test]
    fn post_chain_rejects_broken_linkage() {
        let (mut manifest, id, checkpoint, new_chain) = halt_test_pair();
        // Flip a byte inside `previous` (offset 78..110), past the embedded
        // height: the header no longer hash-links to H.
        let mut raw = hex::decode(manifest.halt_post_blocks.as_ref().unwrap()[0].clone()).unwrap();
        raw[80] ^= 1;
        manifest.halt_post_blocks.as_mut().unwrap()[0] = hex::encode(&raw);
        assert!(
            verify_migration_halt_pair(
                &manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err(),
            "a post-H block that does not hash-link must fail"
        );
    }

    #[test]
    fn post_chain_rejects_a_sibling_staged_under_the_wrong_id() {
        let (mut manifest, id, checkpoint, new_chain) = halt_test_pair();
        // Flip a byte in the last staged id past its embedded height: the
        // height bytes still name block 9, but the id is no longer the
        // header's. The walk must derive the id instead of trusting it, so
        // an empty sibling smuggled under the real block's number fails.
        let mut raw = hex::decode(manifest.halt_post_blocks.as_ref().unwrap()[1].clone()).unwrap();
        let id_off = raw.len() - 32;
        assert_eq!(&raw[id_off..id_off + 4], &9u32.to_be_bytes());
        raw[id_off + 4] ^= 1;
        manifest.halt_post_blocks.as_mut().unwrap()[1] = hex::encode(&raw);
        let err = verify_migration_halt_pair(
            &manifest,
            7,
            &id,
            &checkpoint,
            &new_chain,
            TEST_SCHEDULE_VERSION,
            Some(&TEST_PLATFORM_ID),
        )
        .unwrap_err();
        assert!(
            err.contains("id"),
            "a post-H block whose id does not derive from its header must fail, got: {err}"
        );
    }

    #[test]
    fn post_chain_rejects_non_empty_blocks() {
        let (manifest, id, checkpoint, new_chain) = halt_test_pair();
        let k = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("pair-1").unwrap();
        let k2 = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("pair-2").unwrap();
        let prod_a = pulsevm_name::Name::from_str("prod.a").unwrap().as_u64();
        let prod_b = pulsevm_name::Name::from_str("prod.b").unwrap().as_u64();
        // The tampered header stays first in a full two-block window (the
        // attested pause head is 9): the gate must reject the content, not
        // the coverage.
        let sched = FIXTURE_SCHEDULE_HASH;
        let chain_from = |first: &str, first_id: &[u8; 32]| {
            let (second, _) = pack_post_block(
                first_id,
                prod_b,
                &k2,
                TEST_SCHEDULE_VERSION,
                0,
                [0u8; 32],
                false,
                &[],
                [9u8; 32],
                sched,
                true,
            );
            vec![first.to_string(), second]
        };
        // A block that lists a transaction is not empty, even with a zero root.
        let (with_tx, tx_id) = pack_post_block(
            &id,
            prod_a,
            &k,
            TEST_SCHEDULE_VERSION,
            1,
            [0u8; 32],
            false,
            &[],
            [8u8; 32],
            sched,
            true,
        );
        let mut tampered = manifest.clone();
        tampered.halt_post_blocks = Some(chain_from(&with_tx, &tx_id));
        assert!(
            verify_migration_halt_pair(
                &tampered,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err(),
            "a post-H block carrying transactions must fail"
        );
        // A zero-transaction block with a non-zero root is tampered all the same.
        let (bad_root, root_id) = pack_post_block(
            &id,
            prod_a,
            &k,
            TEST_SCHEDULE_VERSION,
            0,
            [7u8; 32],
            false,
            &[],
            [8u8; 32],
            sched,
            true,
        );
        tampered.halt_post_blocks = Some(chain_from(&bad_root, &root_id));
        assert!(
            verify_migration_halt_pair(
                &tampered,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err(),
            "a post-H block with a non-empty transaction root must fail"
        );
    }

    #[test]
    fn post_chain_rejects_foreign_signatures_and_rotations() {
        let (manifest, id, checkpoint, new_chain) = halt_test_pair();
        let outsider = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("post-outsider").unwrap();
        let k = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("pair-1").unwrap();
        let k2 = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("pair-2").unwrap();
        let prod_a = pulsevm_name::Name::from_str("prod.a").unwrap().as_u64();
        let prod_b = pulsevm_name::Name::from_str("prod.b").unwrap().as_u64();
        // The tampered header stays first in a full two-block window (the
        // attested pause head is 9): the gate must reject the content, not
        // the coverage.
        let sched = FIXTURE_SCHEDULE_HASH;
        let chain_from = |first: &str, first_id: &[u8; 32]| {
            let (second, _) = pack_post_block(
                first_id,
                prod_b,
                &k2,
                TEST_SCHEDULE_VERSION,
                0,
                [0u8; 32],
                false,
                &[],
                [9u8; 32],
                sched,
                true,
            );
            vec![first.to_string(), second]
        };
        // Signed by a key no schedule member holds: not a producer block.
        let (forged, forged_id) = pack_post_block(
            &id,
            prod_a,
            &outsider,
            TEST_SCHEDULE_VERSION,
            0,
            [0u8; 32],
            false,
            &[],
            [8u8; 32],
            sched,
            true,
        );
        let mut tampered = manifest.clone();
        tampered.halt_post_blocks = Some(chain_from(&forged, &forged_id));
        assert!(
            verify_migration_halt_pair(
                &tampered,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err(),
            "a post-H block with a foreign signature must fail"
        );
        // A schedule change inside the window changes the frozen set.
        let (rotated, rotated_id) = pack_post_block(
            &id,
            prod_a,
            &k,
            TEST_SCHEDULE_VERSION,
            0,
            [0u8; 32],
            true,
            &[],
            [8u8; 32],
            sched,
            true,
        );
        tampered.halt_post_blocks = Some(chain_from(&rotated, &rotated_id));
        assert!(
            verify_migration_halt_pair(
                &tampered,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err(),
            "a post-H schedule change must fail"
        );
        // A rotated version on an otherwise valid header fails the same way.
        let (wrong_version, version_id) = pack_post_block(
            &id,
            prod_a,
            &k,
            TEST_SCHEDULE_VERSION + 1,
            0,
            [0u8; 32],
            false,
            &[],
            [8u8; 32],
            sched,
            true,
        );
        tampered.halt_post_blocks = Some(chain_from(&wrong_version, &version_id));
        assert!(
            verify_migration_halt_pair(
                &tampered,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err(),
            "a post-H version rotation must fail"
        );
    }

    #[test]
    fn post_chain_rejects_missing_and_mismatched_schedule() {
        let (manifest, id, checkpoint, new_chain) = halt_test_pair();
        let run = |manifest: &MigrationManifest| {
            verify_migration_halt_pair(
                manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID),
            )
            .is_err()
        };
        // Unattested windows and schedules fail closed, even with a valid pair.
        let mut missing = manifest.clone();
        missing.halt_post_blocks = None;
        assert!(run(&missing), "missing post-H evidence must fail");
        let mut missing_schedule = manifest.clone();
        missing_schedule.halt_schedule = None;
        assert!(
            run(&missing_schedule),
            "missing recorded schedule must fail"
        );
        // The recorded schedule must equal the declared set: an extra
        // member, a dropped member, or a moved key all fail.
        let mut extra = manifest.clone();
        extra
            .halt_schedule
            .as_mut()
            .unwrap()
            .push(MigrationHaltRosterEntry {
                producer: "prod.zz".to_string(),
                key: test_key("schedule-extra").to_string(),
                weight: pulsevm_chain_types::HaltWeight::MEMBER,
            });
        assert!(run(&extra), "a schedule larger than declared must fail");
        let mut dropped = manifest.clone();
        dropped.halt_schedule.as_mut().unwrap().pop();
        assert!(run(&dropped), "a schedule smaller than declared must fail");
        let mut moved = manifest.clone();
        moved.halt_schedule.as_mut().unwrap()[0].key = test_key("schedule-moved").to_string();
        assert!(run(&moved), "a schedule with a moved key must fail");
        let mut weighted = manifest.clone();
        weighted.halt_schedule.as_mut().unwrap()[0].weight = pulsevm_chain_types::HaltWeight(50);
        assert!(run(&weighted), "a non-unit recorded weight must fail");
    }

    #[test]
    fn post_chain_rejects_gaps_and_overlong_windows() {
        let (manifest, id, checkpoint, new_chain) = halt_test_pair();
        let k = pulsevm_crypto::k1::K1PrivateKey::from_seed_string("pair-1").unwrap();
        let prod_a = pulsevm_name::Name::from_str("prod.a").unwrap().as_u64();
        let sched = FIXTURE_SCHEDULE_HASH;
        let run = |blocks: Vec<String>| {
            let mut tampered = manifest.clone();
            tampered.halt_post_blocks = Some(blocks);
            verify_migration_halt_pair(
                &tampered,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID),
            )
            .is_err()
        };
        // A skipped height: after block 8 the walk expects 9, but the
        // second header's parent embeds 9, demanding 10 — the follow
        // check breaks the chain.
        let (post8, id8) = pack_post_block(
            &id,
            prod_a,
            &k,
            TEST_SCHEDULE_VERSION,
            0,
            [0u8; 32],
            false,
            &[],
            [8u8; 32],
            sched,
            true,
        );
        let mut jumped = id8;
        jumped[0..4].copy_from_slice(&9u32.to_be_bytes());
        let (post10, _) = pack_post_block(
            &jumped,
            prod_a,
            &k,
            TEST_SCHEDULE_VERSION,
            0,
            [0u8; 32],
            false,
            &[],
            [10u8; 32],
            sched,
            true,
        );
        assert!(run(vec![post8, post10]), "a skipped height must fail");
        // A window past the bound fails closed no matter how well formed.
        let mut chained = Vec::new();
        let mut prev = id;
        for _ in 0..=MAX_POST_H_BLOCKS {
            let (packed, next) = pack_post_block(
                &prev,
                prod_a,
                &k,
                TEST_SCHEDULE_VERSION,
                0,
                [0u8; 32],
                false,
                &[],
                [8u8; 32],
                sched,
                true,
            );
            chained.push(packed);
            prev = next;
        }
        assert!(run(chained), "an overlong post-H window must fail");
    }

    #[test]
    fn verify_migration_halt_pair_replays_contract_evidence() {
        // The pair fixture already carries the on-chain ceremony (both
        // votes before H, finalized singleton, matching tally).
        let (manifest, id, checkpoint, new_chain) = halt_test_pair();
        verify_migration_halt_pair(
            &manifest,
            7,
            &id,
            &checkpoint,
            &new_chain,
            TEST_SCHEDULE_VERSION,
            Some(&TEST_PLATFORM_ID),
        )
        .expect("pair with contract evidence must verify");
        // A pair stripped of its ceremony and with no recorded inclusion
        // proves no pre-commitment timing: off-chain signatures alone say
        // nothing about when they were made.
        let mut bare = manifest.clone();
        bare.halt_contract_ceremony = None;
        assert!(
            verify_migration_halt_pair(
                &bare,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        // The memo vehicle records the digest on-chain instead: a recorded
        // in-window inclusion with no ceremony still verifies. The schedule
        // version pin still applies: unanimity must be on the record even
        // without per-vote evidence.
        let mut memo = manifest.clone();
        memo.halt_contract_ceremony = None;
        memo.halt_declaration_inclusion = Some(5);
        verify_migration_halt_pair(
            &memo,
            7,
            &id,
            &checkpoint,
            &new_chain,
            TEST_SCHEDULE_VERSION,
            Some(&TEST_PLATFORM_ID),
        )
        .expect("recorded declaration inclusion proves pre-commitment timing");
        // Contract evidence without the attested schedule version fails:
        // unanimity across the window must be on the record.
        let mut unversioned = manifest.clone();
        unversioned.halt_schedule_version = None;
        assert!(
            verify_migration_halt_pair(
                &unversioned,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        // A vote landing at H is not a pre-commitment: the evidence fails.
        let mut late = manifest.clone();
        late.halt_contract_ceremony
            .as_mut()
            .expect("evidence attached")
            .votes[1]
            .block = 7;
        assert!(
            verify_migration_halt_pair(
                &late,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        // A captured tally divorced from the recomputed signer weight fails.
        let mut inflated = manifest.clone();
        inflated
            .halt_contract_ceremony
            .as_mut()
            .expect("evidence attached")
            .voted_weight = pulsevm_chain_types::HaltWeight(4);
        assert!(
            verify_migration_halt_pair(
                &inflated,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
    }

    #[test]
    fn verify_migration_halt_pair_enforces_version_and_platform_pins() {
        let (manifest, id, checkpoint, new_chain) = halt_test_pair();
        verify_migration_halt_pair(
            &manifest,
            7,
            &id,
            &checkpoint,
            &new_chain,
            TEST_SCHEDULE_VERSION,
            Some(&TEST_PLATFORM_ID),
        )
        .expect("pair fixture must verify");
        // A vote from another schedule version fails: the schedule rotated
        // mid-ceremony and the freeze no longer names one set.
        let mut rotated = manifest.clone();
        rotated
            .halt_contract_ceremony
            .as_mut()
            .expect("evidence attached")
            .votes[0]
            .schedule_version = TEST_SCHEDULE_VERSION + 1;
        assert!(
            verify_migration_halt_pair(
                &rotated,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        // The attested version must equal H's version, not merely exist: a
        // version the exporter asserts without matching H fails closed.
        let mut misattested = manifest.clone();
        misattested.halt_schedule_version = Some(TEST_SCHEDULE_VERSION + 1);
        assert!(
            verify_migration_halt_pair(
                &misattested,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        // H under another version fails even with unanimous votes.
        assert!(
            verify_migration_halt_pair(
                &manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION + 1,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        // A confirmation bound to another platform fails: wallets would
        // sign under a different id than the ceremony committed to.
        let other_platform = [0x52; 32];
        assert!(
            verify_migration_halt_pair(
                &manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&other_platform)
            )
            .is_err()
        );
        // A confirmation stripped of its platform binding fails closed:
        // version 2 has no unbound form, so the digest itself rejects it
        // before any signature is checked.
        let mut unbound = manifest.clone();
        unbound
            .halt_confirmation
            .as_mut()
            .expect("confirmation attached")
            .platform_chain_id = String::new();
        assert!(
            verify_migration_halt_pair(
                &unbound,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        // A checkpoint carrying a proposed schedule fails closed: the
        // ceremony never froze the pending proposal.
        let mut proposed = manifest.clone();
        proposed.halt_proposed_schedule = Some(true);
        assert!(
            verify_migration_halt_pair(
                &proposed,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        // An unattested checkpoint fails the same way: absence must be on
        // the record, not assumed.
        let mut unattested = manifest.clone();
        unattested.halt_proposed_schedule = None;
        assert!(
            verify_migration_halt_pair(
                &unattested,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
    }

    #[test]
    fn verify_migration_halt_pair_rejects_signer_weight_inflation() {
        // Move weight onto a signer in the declaration only: the frozen
        // singleton still pins the old tally and the quorum signatures bind
        // the old digest, so the inflated declaration verifies against
        // nothing. Either layer fails the pair closed.
        let (mut manifest, id, checkpoint, new_chain) = halt_test_pair();
        manifest
            .halt_declaration
            .as_mut()
            .expect("declaration attached")
            .validator_set[0]
            .weight = pulsevm_chain_types::HaltWeight(3);
        assert!(
            verify_migration_halt_pair(
                &manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
    }

    #[test]
    fn verify_migration_halt_pair_rejects_missing_steps() {
        let (mut manifest, id, checkpoint, new_chain) = halt_test_pair();
        manifest.halt_confirmation = None;
        assert!(
            verify_migration_halt_pair(
                &manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        let (mut manifest, id, checkpoint, new_chain) = halt_test_pair();
        manifest.halt_declaration = None;
        assert!(
            verify_migration_halt_pair(
                &manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
    }

    #[test]
    fn verify_migration_halt_pair_enforces_vote_windows() {
        // Declaration committed two blocks before H, inside a lag-10
        // window; confirmation quorum recorded two blocks after H inside a
        // 10-block deadline: the timing is provable and valid.
        let (mut manifest, id, checkpoint, new_chain) = halt_test_pair();
        manifest.halt_declaration_inclusion = Some(5);
        manifest.halt_max_declaration_lag = Some(10);
        manifest.halt_confirmation_inclusion = Some(9);
        manifest.halt_max_confirmation_lag = Some(10);
        verify_migration_halt_pair(
            &manifest,
            7,
            &id,
            &checkpoint,
            &new_chain,
            TEST_SCHEDULE_VERSION,
            Some(&TEST_PLATFORM_ID),
        )
        .expect("in-window inclusions must verify");
        // A declaration at H itself is not a pre-commitment: H must stay
        // empty and the commitment must predate it.
        manifest.halt_declaration_inclusion = Some(7);
        assert!(
            verify_migration_halt_pair(
                &manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        // A stale declaration (older than H-K) fails the freshness bound.
        manifest.halt_declaration_inclusion = Some(5);
        manifest.halt_max_declaration_lag = Some(1);
        assert!(
            verify_migration_halt_pair(
                &manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        manifest.halt_max_declaration_lag = Some(10);
        // A confirmation at H itself is circular: it references H_ID,
        // which cannot exist inside H.
        manifest.halt_confirmation_inclusion = Some(7);
        assert!(
            verify_migration_halt_pair(
                &manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        // A confirmation past its deadline fails closed.
        manifest.halt_confirmation_inclusion = Some(9);
        manifest.halt_max_confirmation_lag = Some(1);
        assert!(
            verify_migration_halt_pair(
                &manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
    }

    #[test]
    fn halt_inclusion_window_handles_boundaries() {
        // No inclusions recorded: off-chain path, skipped.
        assert!(check_halt_inclusion_window(7, None, None, None, None).is_ok());
        // Structural bounds without claimed K/J.
        assert!(check_halt_inclusion_window(7, Some(6), None, None, None).is_ok());
        assert!(check_halt_inclusion_window(7, Some(7), None, None, None).is_err());
        assert!(check_halt_inclusion_window(7, None, None, Some(8), None).is_ok());
        assert!(check_halt_inclusion_window(7, None, None, Some(7), None).is_err());
        // Zero height: nothing can predate it.
        assert!(check_halt_inclusion_window(0, Some(0), None, None, None).is_err());
        // Saturating arithmetic near u32::MAX: no panic, bounds enforced.
        assert!(
            check_halt_inclusion_window(u32::MAX, Some(u32::MAX - 1), Some(10), None, None).is_ok()
        );
        assert!(
            check_halt_inclusion_window(u32::MAX, None, None, Some(u32::MAX), Some(0)).is_err()
        );
    }

    #[test]
    fn verify_migration_halt_pair_rejects_divergent_roster_and_chain() {
        let (mut manifest, id, checkpoint, new_chain) = halt_test_pair();
        manifest.halt_roster.as_mut().unwrap()[0].weight = pulsevm_chain_types::HaltWeight(9);
        assert!(
            verify_migration_halt_pair(
                &manifest,
                7,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        let (manifest, id, checkpoint, _) = halt_test_pair();
        assert!(
            verify_migration_halt_pair(
                &manifest,
                7,
                &id,
                &checkpoint,
                &[0x99; 32],
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
        let (manifest, id, checkpoint, new_chain) = halt_test_pair();
        assert!(
            verify_migration_halt_pair(
                &manifest,
                8,
                &id,
                &checkpoint,
                &new_chain,
                TEST_SCHEDULE_VERSION,
                Some(&TEST_PLATFORM_ID)
            )
            .is_err()
        );
    }

    #[test]
    fn migration_manifest_roster_rejects_invalid_key() {
        let checkpoint = crate::snapshot::encode(7, b"checkpoint");
        let manifest = MigrationManifest::new(
            b"source state history",
            [9; 32],
            &checkpoint,
            7,
            ImportSummary::default(),
        )
        .with_halt_roster(vec![MigrationHaltRosterEntry {
            producer: "prod.zz".to_string(),
            key: "not-a-key".to_string(),
            weight: pulsevm_chain_types::HaltWeight(10),
        }]);
        assert!(manifest.roster_entries().is_err());
    }

    fn delta(name: &str, data: Vec<u8>) -> TableDelta {
        TableDelta {
            name: name.into(),
            rows: vec![TableDeltaRow {
                present: true,
                data,
            }],
        }
    }

    fn bytes(out: &mut Vec<u8>, value: &[u8]) {
        assert!(value.len() < 128);
        out.push(value.len() as u8);
        out.extend_from_slice(value);
    }

    fn secondary_prefix(code: u64, scope: u64, table: u64, primary: u64, payer: u64) -> Vec<u8> {
        let mut out = vec![0];
        for value in [code, scope, table, primary, payer] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }
}
