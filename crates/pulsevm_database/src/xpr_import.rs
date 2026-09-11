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
    pub contract_tables: u64,
    pub contract_rows: u64,
    pub index64_rows: u64,
    pub index128_rows: u64,
    pub index256_rows: u64,
    pub index_double_rows: u64,
    pub index_long_double_rows: u64,
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
    /// When the source contains deferred transactions, this commits the
    /// chainbase-sidecar which supplies the timestamps SHiP v0 does not carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferred_transaction_sidecar_sha256: Option<String>,
    pub import_summary: ImportSummary,
}

impl MigrationManifest {
    pub const VERSION: u16 = 1;

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
            import_summary,
        }
    }

    /// Bind this migration manifest to the exact deferred-transaction sidecar
    /// verified during import. The sidecar is intentionally a separate
    /// artifact because SHiP's generated_transaction_v0 projection omits
    /// scheduling timestamps present in XPR chainbase.
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

    /// Verify that `checkpoint` is precisely the artifact this manifest
    /// describes. The checkpoint envelope itself is checked by restore; this
    /// method establishes its migration provenance before restore begins.
    pub fn verify_checkpoint(&self, checkpoint: &[u8]) -> Result<(), String> {
        if self.version != Self::VERSION {
            return Err(format!(
                "unsupported migration manifest version {} (expected {})",
                self.version,
                Self::VERSION
            ));
        }
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
        if self.version != Self::VERSION {
            return Err(format!(
                "unsupported migration manifest version {} (expected {})",
                self.version,
                Self::VERSION
            ));
        }
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

/// A malformed or unsupported XPR state-history input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XprImportError(String);

impl fmt::Display for XprImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for XprImportError {}

/// JSON emitted by the XPR chainbase deferred-transaction sidecar exporter.
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
    pub const VERSION: u16 = 1;

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
        for row in &sidecar.transactions {
            sidecar_key(row)?;
        }
        Ok(sidecar)
    }
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
            version: 1,
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
            version: 1,
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
            version: 1,
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
            version: 1,
            source_block_id: hex::encode([0; 32]),
            source_chain_id: Some(hex::encode([2; 32])),
            account_metadata: vec![],
            code: vec![],
            permissions: vec![],
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
            r#"{{"version":1,"source_block_id":"{}","transactions":[{{"sender":11,"sender_id":"{}","payer":14,"trx_id":"{}","delay_until":1,"expiration":2,"published":0,"packed_trx":"1011"}}]}}"#,
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
                r#"{{"version":1,"source_block_id":"{}","transactions":[{{"sender":11,"sender_id":"{}","payer":14,"trx_id":"{}","delay_until":1,"expiration":2,"published":0,"packed_trx":"1011"}}]}}"#,
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
    fn rejects_deferred_sidecar_from_a_different_block() {
        let sidecar = DeferredTransactionSidecar::from_json_bytes(
            br#"{"version":1,"source_block_id":"0000000000000000000000000000000000000000000000000000000000000000","transactions":[]}"#,
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
