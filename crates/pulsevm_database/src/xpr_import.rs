//! Input boundary for importing an XPR chainbase snapshot into Arena.
//!
//! XPR core's `state_history_plugin` writes the first accepted block in an
//! empty chain-state-history log as a complete set of SHiP `table_delta`s. This
//! module checks that physical log record and exposes the uncompressed table
//! frames. Hydration deliberately lives above this layer: it must make
//! table-specific compatibility decisions rather than treating arbitrary source
//! bytes as an Arena checkpoint.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::Read,
};

use flate2::read::ZlibDecoder;

use crate::{ChainConfigV0, Database, Float128, U256};

/// XPR core writes `magic(8) + block_id(32) + payload_size(8)` before every
/// state-history payload, followed by an eight-byte copy of the record's file
/// offset. These sizes are fixed by `state_history_log_header` in XPR core.
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

/// Counts of the portable rows committed by [`hydrate_full_state`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportSummary {
    pub global_properties: u64,
    pub accounts: u64,
    pub account_metadata: u64,
    pub code_rows: u64,
    pub permissions: u64,
    pub permission_links: u64,
    pub resource_limits: u64,
    pub resource_usage: u64,
    pub contract_tables: u64,
    pub contract_rows: u64,
    pub index64_rows: u64,
    pub index128_rows: u64,
    pub index256_rows: u64,
    pub index_double_rows: u64,
    pub index_long_double_rows: u64,
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
    let rows = decode_portable_rows(entry)?;
    validate_code_links(&rows)?;
    let mut summary = ImportSummary::default();

    db.arena_start_undo_session();
    let result = (|| {
        // The state-history table order happens to be suitable today, but the
        // importer enforces its own dependency order so an equivalent stream
        // with tables rearranged cannot create children before their parents.
        for row in &rows {
            if let PortableRow::GlobalProperty { config } = row {
                db.set_global_properties(config).map_err(database_error)?;
                summary.global_properties += 1;
            }
        }
        for row in &rows {
            match row {
                PortableRow::Account {
                    name,
                    creation_date,
                    abi,
                } => {
                    db.create_account(*name, *creation_date)
                        .map_err(database_error)?;
                    db.xpr_import_set_account_abi_raw(*name, abi)
                        .map_err(database_error)?;
                    summary.accounts += 1;
                }
                _ => {}
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
        for row in rows {
            match row {
                PortableRow::Account { .. }
                | PortableRow::GlobalProperty { .. }
                | PortableRow::EmptyProtocolState
                | PortableRow::PermissionLink { .. }
                | PortableRow::ResourceLimits { .. }
                | PortableRow::ResourceUsage { .. }
                | PortableRow::AccountMetadata { .. }
                | PortableRow::Code { .. }
                | PortableRow::Permission { .. } => {}
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

fn database_error(error: impl fmt::Display) -> XprImportError {
    bad(format!("writing Arena state: {error}"))
}

enum PortableRow {
    /// XPR's producer schedule is deliberately not carried over: the imported
    /// database starts a new Pulse chain with its own producer schedule. Its
    /// chain execution configuration is retained in Arena.
    GlobalProperty { config: ChainConfigV0 },
    /// A source with activated protocol features cannot be treated as a Pulse
    /// runtime without an explicit feature mapping. The empty fixture state is
    /// safe and needs no storage in the target runtime.
    EmptyProtocolState,
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
            let decoded = match delta.name.as_str() {
                "global_property" => decode_global_property(&row.data)?,
                "protocol_state" => decode_empty_protocol_state(&row.data)?,
                "permission_link" => decode_permission_link(&row.data)?,
                "resource_limits" => decode_resource_limits(&row.data)?,
                "resource_usage" => decode_resource_usage(&row.data)?,
                "account" => decode_account(&row.data)?,
                "account_metadata" => decode_account_metadata(&row.data)?,
                "code" => decode_code(&row.data)?,
                "permission" => decode_permission(&row.data)?,
                "contract_table" => decode_contract_table(&row.data)?,
                "contract_row" => decode_contract_row(&row.data)?,
                "contract_index64" => decode_index64(&row.data)?,
                "contract_index128" => decode_index128(&row.data)?,
                "contract_index256" => decode_index256(&row.data)?,
                "contract_index_double" => decode_index_double(&row.data)?,
                "contract_index_long_double" => decode_index_long_double(&row.data)?,
                table => {
                    return Err(bad(format!(
                        "XPR table {table:?} is not supported by the importer yet"
                    )));
                }
            };
            result.push(decoded);
        }
    }
    Ok(result)
}

fn validate_code_links(rows: &[PortableRow]) -> Result<(), XprImportError> {
    let mut code_keys = HashSet::new();
    for row in rows {
        if let PortableRow::Code {
            hash,
            vm_type,
            vm_version,
            ..
        } = row
        {
            if !code_keys.insert((*hash, *vm_type, *vm_version)) {
                return Err(bad("duplicate XPR code row"));
            }
        }
    }
    for row in rows {
        if let PortableRow::AccountMetadata {
            name,
            code: Some(code),
            ..
        } = row
        {
            if !code_keys.contains(&(code.hash, code.vm_type, code.vm_version)) {
                return Err(bad(format!(
                    "account metadata for {name} references code absent from the full-state export"
                )));
            }
        }
    }
    Ok(())
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

    // proposed_schedule_block_num: optional<uint32>
    if row.bool()? {
        row.u32()?;
    }
    skip_producer_authority_schedule(&mut row)?;

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
        deferred_trx_expiration_window: row.u32()?,
        max_transaction_delay: row.u32()?,
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

    row.fixed::<32>()?; // source chain id; the target has a new chain id
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
    Ok(PortableRow::GlobalProperty { config })
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

fn decode_empty_protocol_state(bytes: &[u8]) -> Result<PortableRow, XprImportError> {
    let mut row = RowCursor::new(bytes);
    row.version()?;
    if row.varuint()? != 0 {
        return Err(bad(
            "XPR activated protocol features require an explicit Pulse feature mapping",
        ));
    }
    row.finish()?;
    Ok(PortableRow::EmptyProtocolState)
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
        if row.varuint()? != 0 {
            return Err(bad("XPR authority contains a non-K1 public key"));
        }
        let point = row.fixed::<33>()?;
        let weight = row.u16()?;
        out.extend_from_slice(&34u32.to_le_bytes());
        out.push(0);
        out.extend_from_slice(&point);
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
/// framing disagrees with XPR core's writer instead of attempting recovery from
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
        // XPR core (the original exporter pin): `uint32 compressed_size` plus
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
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{write::ZlibEncoder, Compression};
    use tempfile::TempDir;

    use super::*;

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
