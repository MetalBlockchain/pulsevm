//! Input boundary for importing an XPR chainbase snapshot into Arena.
//!
//! XPR core's `state_history_plugin` writes the first accepted block in an
//! empty chain-state-history log as a complete set of SHiP `table_delta`s. This
//! module checks that physical log record and exposes the uncompressed table
//! frames. Hydration deliberately lives above this layer: it must make
//! table-specific compatibility decisions rather than treating arbitrary source
//! bytes as an Arena checkpoint.

use std::{fmt, io::Read};

use flate2::read::ZlibDecoder;

use crate::{Database, Float128, U256};

/// XPR core writes `magic(8) + block_id(32) + payload_size(8)` before every
/// state-history payload, followed by an eight-byte copy of the record's file
/// offset. These sizes are fixed by `state_history_log_header` in XPR core.
const LOG_HEADER_LEN: usize = 8 + 32 + 8;
const LOG_TRAILER_LEN: usize = 8;
const COMPRESSED_SIZE_LEN: usize = 4;

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
    pub accounts: u64,
    pub account_metadata: u64,
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
/// resource limits, protocol state, generated transactions, and code-bearing
/// account metadata). Accepting those tables while dropping their state would
/// create a network that appears bootable but is invalid at its first action.
///
/// This is therefore a safe, incremental boundary: it can import accounts
/// without deployed code and every contract-table/index row, while making the
/// remaining full-chain work explicit to the caller.
pub fn hydrate_full_state(
    db: &mut Database,
    entry: &StateHistoryEntry,
) -> Result<ImportSummary, XprImportError> {
    let rows = decode_portable_rows(entry)?;
    let mut summary = ImportSummary::default();

    db.arena_start_undo_session();
    let result = (|| {
        for row in rows {
            match row {
                PortableRow::Account {
                    name,
                    creation_date,
                    abi,
                } => {
                    db.create_account(name, creation_date)
                        .map_err(database_error)?;
                    db.xpr_import_set_account_abi_raw(name, &abi)
                        .map_err(database_error)?;
                    summary.accounts += 1;
                }
                PortableRow::AccountMetadata { name, privileged } => {
                    db.create_account_metadata(name, privileged)
                        .map_err(database_error)?;
                    summary.account_metadata += 1;
                }
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
    Account {
        name: u64,
        creation_date: u32,
        abi: Vec<u8>,
    },
    AccountMetadata {
        name: u64,
        privileged: bool,
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
                "account" => decode_account(&row.data)?,
                "account_metadata" => decode_account_metadata(&row.data)?,
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
    let _last_code_update = row.i64()?;
    if row.bool()? {
        return Err(bad(
            "code-bearing account metadata is not supported by the importer yet",
        ));
    }
    row.finish()?;
    Ok(PortableRow::AccountMetadata { name, privileged })
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
    if bytes.len() < LOG_HEADER_LEN + COMPRESSED_SIZE_LEN + LOG_TRAILER_LEN {
        return Err(bad("state-history log is too short"));
    }

    let magic = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    if (magic as u32) != 0 {
        return Err(bad(format!(
            "unsupported XPR state-history version {}",
            magic as u32
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
    if payload.len() < COMPRESSED_SIZE_LEN {
        return Err(bad("state-history payload is missing compressed length"));
    }
    let compressed_len = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    if compressed_len != payload.len() - COMPRESSED_SIZE_LEN {
        return Err(bad(format!(
            "state-history compressed length {compressed_len} does not match payload {}",
            payload.len() - COMPRESSED_SIZE_LEN
        )));
    }

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

    let mut decoder = ZlibDecoder::new(&payload[COMPRESSED_SIZE_LEN..]);
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

        let mut account_row = vec![0];
        account_row.extend_from_slice(&account.to_le_bytes());
        account_row.extend_from_slice(&7u32.to_le_bytes());
        bytes(&mut account_row, &[0xaa, 0xbb]);

        let mut metadata_row = vec![0];
        metadata_row.extend_from_slice(&account.to_le_bytes());
        metadata_row.push(1); // privileged
        metadata_row.extend_from_slice(&0i64.to_le_bytes());
        metadata_row.push(0); // no code

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
        assert_eq!(summary.contract_tables, 1);
        assert_eq!(summary.contract_rows, 1);
        assert_eq!(summary.index64_rows, 1);
        assert_eq!(summary.index128_rows, 1);
        assert_eq!(summary.index256_rows, 1);
        assert_eq!(summary.index_double_rows, 1);
        assert_eq!(summary.index_long_double_rows, 1);
        assert!(db.is_account(account).unwrap());
        assert_eq!(db.arena_account_metadata_privileged(account), Some(true));
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
