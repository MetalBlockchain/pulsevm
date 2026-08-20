//! Input boundary for importing an XPR chainbase snapshot into Arena.
//!
//! XPR core's `state_history_plugin` writes the first accepted block in an
//! empty chain-state-history log as a complete set of SHiP `table_delta`s. This
//! module checks that physical log record and exposes the uncompressed table
//! frames. Hydration deliberately lives above this layer: it must make
//! table-specific compatibility decisions rather than treating arbitrary source
//! bytes as an Arena checkpoint.

use std::{
    fmt,
    io::Read,
};

use flate2::read::ZlibDecoder;

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

/// A malformed or unsupported XPR state-history input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XprImportError(String);

impl fmt::Display for XprImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for XprImportError {}

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
        let name = String::from_utf8(name)
            .map_err(|_| bad("table-delta name is not valid UTF-8"))?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            return Err(bad(format!("invalid table-delta name {name:?}")));
        }

        let row_count = cursor.varuint()?;
        let row_count = usize::try_from(row_count)
            .map_err(|_| bad("row count does not fit this platform"))?;
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

    use flate2::{
        Compression,
        write::ZlibEncoder,
    };

    use super::*;

    #[test]
    fn parses_full_state_history_entry() {
        // Two table_delta values: account has one live payload, and code has a
        // single empty removal. Hydration later rejects that removal; decoding
        // preserves it so validation can report the source error precisely.
        let raw = [
            2, // table count
            0, 7, b'a', b'c', b'c', b'o', b'u', b'n', b't', 1, 1, 3, 1, 2, 3,
            0, 4, b'c', b'o', b'd', b'e', 1, 0, 0,
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
}
