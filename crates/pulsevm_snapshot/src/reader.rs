use std::marker::PhantomData;

use pulsevm_serialization::Read;

use crate::{
    contract_tables::ContractTablesReader,
    error::SnapshotError,
    rows::{
        AccountMetadataRow,
        AccountRamCorrectionRow,
        AccountRow,
        BlockHeaderState,
        BlockSummaryRow,
        ChainSnapshotHeader,
        CodeRow,
        DynamicGlobalPropertyRow,
        GeneratedTransactionRow,
        GlobalPropertyRow,
        PermissionLinkRow,
        PermissionRow,
        ProtocolStateRow,
        ResourceLimitsConfigRow,
        ResourceLimitsRow,
        ResourceLimitsStateRow,
        ResourceUsageRow,
        TransactionRow,
        section_names,
    },
};

/// `ostream_snapshot_writer::magic_number`.
pub const SNAPSHOT_MAGIC: u32 = 0x30510550;

/// The container framing version (`current_snapshot_version` in
/// `snapshot.cpp`) — distinct from the chainstate schema version carried by
/// the `chain_snapshot_header` section.
pub const CONTAINER_VERSION: u32 = 1;

/// Chainstate schema versions this crate's row types decode. Version 6 is
/// what Leap/Spring 5.x `create_snapshot` emits.
pub const SUPPORTED_CHAIN_SNAPSHOT_VERSIONS: std::ops::RangeInclusive<u32> = 6..=6;

const END_MARKER: u64 = u64::MAX;

/// One section located in the file: its name, declared row count, and the
/// byte range of its row payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionInfo {
    pub name: String,
    pub row_count: u64,
    /// Offset of the first row byte within the snapshot file.
    pub offset: usize,
    /// Length of the row payload in bytes.
    pub len: usize,
}

/// A parsed snapshot: the section table plus typed access to each section's
/// rows. Borrows the snapshot bytes; nothing is decoded until asked for.
pub struct SnapshotReader<'a> {
    bytes: &'a [u8],
    sections: Vec<SectionInfo>,
    chain_version: u32,
}

fn read_u32(bytes: &[u8], pos: &mut usize, what: &'static str) -> Result<u32, SnapshotError> {
    let end = pos.checked_add(4).filter(|e| *e <= bytes.len());
    let Some(end) = end else {
        return Err(SnapshotError::Truncated(what));
    };
    let value = u32::from_le_bytes(bytes[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(value)
}

fn read_u64(bytes: &[u8], pos: &mut usize, what: &'static str) -> Result<u64, SnapshotError> {
    let end = pos.checked_add(8).filter(|e| *e <= bytes.len());
    let Some(end) = end else {
        return Err(SnapshotError::Truncated(what));
    };
    let value = u64::from_le_bytes(bytes[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(value)
}

impl<'a> SnapshotReader<'a> {
    /// Parse the container: validate magic and versions and build the section
    /// table. Row payloads are not touched (beyond the one-row header
    /// section), so this is cheap even on a multi-gigabyte snapshot.
    pub fn new(bytes: &'a [u8]) -> Result<Self, SnapshotError> {
        let mut pos = 0usize;
        let magic = read_u32(bytes, &mut pos, "magic number")?;
        if magic != SNAPSHOT_MAGIC {
            return Err(SnapshotError::BadMagic(magic));
        }
        let container_version = read_u32(bytes, &mut pos, "container version")?;
        if container_version != CONTAINER_VERSION {
            return Err(SnapshotError::UnsupportedContainerVersion(
                container_version,
            ));
        }

        let mut sections = Vec::new();
        loop {
            if pos == bytes.len() {
                // Tolerate a missing end marker at EOF.
                break;
            }
            let section_size = read_u64(bytes, &mut pos, "section size")?;
            if section_size == END_MARKER {
                break;
            }
            let section_end = (pos as u64)
                .checked_add(section_size)
                .filter(|e| *e <= bytes.len() as u64)
                .ok_or(SnapshotError::Truncated("section body"))?
                as usize;
            let row_count = read_u64(&bytes[..section_end], &mut pos, "section row count")?;
            let name_end = bytes[pos..section_end]
                .iter()
                .position(|b| *b == 0)
                .map(|i| pos + i)
                .ok_or(SnapshotError::Truncated("section name"))?;
            let name = std::str::from_utf8(&bytes[pos..name_end])
                .map_err(|_| SnapshotError::BadSectionName)?
                .to_string();
            pos = name_end + 1;
            sections.push(SectionInfo {
                name,
                row_count,
                offset: pos,
                len: section_end - pos,
            });
            pos = section_end;
        }

        let mut reader = SnapshotReader {
            bytes,
            sections,
            chain_version: 0,
        };
        let header: ChainSnapshotHeader =
            reader.single_row(section_names::CHAIN_SNAPSHOT_HEADER)?;
        if !SUPPORTED_CHAIN_SNAPSHOT_VERSIONS.contains(&header.version) {
            return Err(SnapshotError::UnsupportedChainVersion(header.version));
        }
        reader.chain_version = header.version;
        Ok(reader)
    }

    /// The chainstate schema version from the `chain_snapshot_header` section.
    pub fn chain_version(&self) -> u32 {
        self.chain_version
    }

    /// The section table, in file order.
    pub fn sections(&self) -> &[SectionInfo] {
        &self.sections
    }

    pub fn has_section(&self, name: &str) -> bool {
        self.sections.iter().any(|s| s.name == name)
    }

    /// A cursor over one section's raw rows.
    pub fn section(&self, name: &str) -> Result<SectionReader<'a>, SnapshotError> {
        let info = self
            .sections
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| SnapshotError::SectionNotFound(name.to_string()))?;
        Ok(SectionReader {
            name: info.name.clone(),
            bytes: &self.bytes[info.offset..info.offset + info.len],
            pos: 0,
            row_count: info.row_count,
            rows_read: 0,
        })
    }

    fn rows<T: Read>(&self, name: &str) -> Result<RowIter<'a, T>, SnapshotError> {
        Ok(RowIter {
            section: self.section(name)?,
            done: false,
            _marker: PhantomData,
        })
    }

    fn single_row<T: Read>(&self, name: &str) -> Result<T, SnapshotError> {
        let mut section = self.section(name)?;
        let row = section.read_row::<T>()?;
        section.finish()?;
        Ok(row)
    }

    /// The head `block_header_state` the snapshot was taken at — block num,
    /// id, timestamp and producer schedule for height continuity.
    pub fn block_header_state(&self) -> Result<BlockHeaderState, SnapshotError> {
        self.single_row(section_names::BLOCK_STATE)
    }

    pub fn accounts(&self) -> Result<RowIter<'a, AccountRow>, SnapshotError> {
        self.rows(section_names::ACCOUNT)
    }

    pub fn account_metadata(&self) -> Result<RowIter<'a, AccountMetadataRow>, SnapshotError> {
        self.rows(section_names::ACCOUNT_METADATA)
    }

    pub fn account_ram_corrections(
        &self,
    ) -> Result<RowIter<'a, AccountRamCorrectionRow>, SnapshotError> {
        self.rows(section_names::ACCOUNT_RAM_CORRECTION)
    }

    pub fn global_property(&self) -> Result<GlobalPropertyRow, SnapshotError> {
        self.single_row(section_names::GLOBAL_PROPERTY)
    }

    pub fn protocol_state(&self) -> Result<ProtocolStateRow, SnapshotError> {
        self.single_row(section_names::PROTOCOL_STATE)
    }

    pub fn dynamic_global_property(&self) -> Result<DynamicGlobalPropertyRow, SnapshotError> {
        self.single_row(section_names::DYNAMIC_GLOBAL_PROPERTY)
    }

    pub fn block_summaries(&self) -> Result<RowIter<'a, BlockSummaryRow>, SnapshotError> {
        self.rows(section_names::BLOCK_SUMMARY)
    }

    pub fn transactions(&self) -> Result<RowIter<'a, TransactionRow>, SnapshotError> {
        self.rows(section_names::TRANSACTION)
    }

    pub fn generated_transactions(
        &self,
    ) -> Result<RowIter<'a, GeneratedTransactionRow>, SnapshotError> {
        self.rows(section_names::GENERATED_TRANSACTION)
    }

    pub fn code(&self) -> Result<RowIter<'a, CodeRow>, SnapshotError> {
        self.rows(section_names::CODE)
    }

    /// The interleaved `contract_tables` section: every contract table with
    /// its key-value rows and secondary-index rows.
    pub fn contract_tables(&self) -> Result<ContractTablesReader<'a>, SnapshotError> {
        Ok(ContractTablesReader::new(
            self.section(section_names::CONTRACT_TABLES)?,
        ))
    }

    pub fn permissions(&self) -> Result<RowIter<'a, PermissionRow>, SnapshotError> {
        self.rows(section_names::PERMISSION)
    }

    pub fn permission_links(&self) -> Result<RowIter<'a, PermissionLinkRow>, SnapshotError> {
        self.rows(section_names::PERMISSION_LINK)
    }

    pub fn resource_limits(&self) -> Result<RowIter<'a, ResourceLimitsRow>, SnapshotError> {
        self.rows(section_names::RESOURCE_LIMITS)
    }

    pub fn resource_usage(&self) -> Result<RowIter<'a, ResourceUsageRow>, SnapshotError> {
        self.rows(section_names::RESOURCE_USAGE)
    }

    pub fn resource_limits_state(&self) -> Result<ResourceLimitsStateRow, SnapshotError> {
        self.single_row(section_names::RESOURCE_LIMITS_STATE)
    }

    pub fn resource_limits_config(&self) -> Result<ResourceLimitsConfigRow, SnapshotError> {
        self.single_row(section_names::RESOURCE_LIMITS_CONFIG)
    }
}

/// A cursor over one section's rows.
pub struct SectionReader<'a> {
    name: String,
    bytes: &'a [u8],
    pos: usize,
    row_count: u64,
    rows_read: u64,
}

impl<'a> SectionReader<'a> {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Rows declared by the section header. For `contract_tables` this counts
    /// every physical row: table rows, per-index count rows and data rows.
    pub fn row_count(&self) -> u64 {
        self.row_count
    }

    pub fn rows_read(&self) -> u64 {
        self.rows_read
    }

    /// Decode the next row. Rows are byte-contiguous; a decode that leaves the
    /// cursor misaligned will surface as a decode error or a [`finish`]
    /// failure, never as silently wrong data for later sections.
    ///
    /// [`finish`]: SectionReader::finish
    pub fn read_row<T: Read>(&mut self) -> Result<T, SnapshotError> {
        if self.rows_read >= self.row_count {
            return Err(SnapshotError::RowCountMismatch {
                section: self.name.clone(),
                expected: self.row_count,
                actual: self.rows_read + 1,
            });
        }
        let row = T::read(self.bytes, &mut self.pos).map_err(|source| SnapshotError::Decode {
            section: self.name.clone(),
            row: self.rows_read,
            source,
        })?;
        self.rows_read += 1;
        Ok(row)
    }

    /// Assert the section was consumed exactly: all declared rows read and no
    /// bytes left over. This is what makes the row schemas self-verifying
    /// against a real snapshot.
    pub fn finish(&self) -> Result<(), SnapshotError> {
        if self.rows_read != self.row_count {
            return Err(SnapshotError::RowCountMismatch {
                section: self.name.clone(),
                expected: self.row_count,
                actual: self.rows_read,
            });
        }
        if self.pos != self.bytes.len() {
            return Err(SnapshotError::TrailingBytes {
                section: self.name.clone(),
                remaining: self.bytes.len() - self.pos,
            });
        }
        Ok(())
    }
}

/// Iterator over a plain row-list section. Yields exactly the declared number
/// of rows, then verifies the section was consumed byte-exactly (a schema
/// mismatch surfaces as a trailing error item).
pub struct RowIter<'a, T: Read> {
    section: SectionReader<'a>,
    done: bool,
    _marker: PhantomData<T>,
}

impl<'a, T: Read> RowIter<'a, T> {
    pub fn row_count(&self) -> u64 {
        self.section.row_count()
    }
}

impl<'a, T: Read> Iterator for RowIter<'a, T> {
    type Item = Result<T, SnapshotError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if self.section.rows_read() == self.section.row_count() {
            self.done = true;
            return self.section.finish().err().map(Err);
        }
        match self.section.read_row::<T>() {
            Ok(row) => Some(Ok(row)),
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use pulsevm_name::Name;
    use pulsevm_serialization::Write;

    use super::*;
    use crate::rows::TableIdRow;

    fn section(name: &str, row_count: u64, rows: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let section_size = 8 + name.len() as u64 + 1 + rows.len() as u64;
        out.extend(section_size.to_le_bytes());
        out.extend(row_count.to_le_bytes());
        out.extend(name.as_bytes());
        out.push(0);
        out.extend(rows);
        out
    }

    fn container(sections: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(SNAPSHOT_MAGIC.to_le_bytes());
        out.extend(CONTAINER_VERSION.to_le_bytes());
        for s in sections {
            out.extend(s);
        }
        out.extend(END_MARKER.to_le_bytes());
        out
    }

    fn header_section() -> Vec<u8> {
        section(section_names::CHAIN_SNAPSHOT_HEADER, 1, &6u32.to_le_bytes())
    }

    fn account_row(name: &str, creation_slot: u32, abi: &[u8]) -> Vec<u8> {
        let mut row = name.parse::<Name>().unwrap().pack().unwrap();
        row.extend(creation_slot.to_le_bytes());
        row.push(abi.len() as u8); // varuint length, single byte for small abis
        row.extend(abi);
        row
    }

    #[test]
    fn parses_a_minimal_snapshot() {
        let mut rows = account_row("protonnz", 42, b"");
        rows.extend(account_row("eosio", 0, b"abi!"));
        let bytes = container(&[header_section(), section(section_names::ACCOUNT, 2, &rows)]);

        let snapshot = SnapshotReader::new(&bytes).unwrap();
        assert_eq!(snapshot.chain_version(), 6);
        assert_eq!(snapshot.sections().len(), 2);
        assert!(snapshot.has_section(section_names::ACCOUNT));

        let accounts: Vec<_> = snapshot
            .accounts()
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].name, "protonnz".parse::<Name>().unwrap());
        assert_eq!(accounts[0].creation_date.slot(), 42);
        assert!(accounts[0].abi.0.is_empty());
        assert_eq!(accounts[1].abi.0, b"abi!");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = container(&[header_section()]);
        bytes[0] ^= 0xff;
        assert!(matches!(
            SnapshotReader::new(&bytes),
            Err(SnapshotError::BadMagic(_))
        ));
    }

    #[test]
    fn rejects_unsupported_chain_version() {
        let header = section(
            section_names::CHAIN_SNAPSHOT_HEADER,
            1,
            &99u32.to_le_bytes(),
        );
        let bytes = container(&[header]);
        assert!(matches!(
            SnapshotReader::new(&bytes),
            Err(SnapshotError::UnsupportedChainVersion(99))
        ));
    }

    #[test]
    fn rejects_truncated_section() {
        let bytes_full = container(&[header_section()]);
        let bytes = &bytes_full[..bytes_full.len() - 12];
        assert!(matches!(
            SnapshotReader::new(bytes),
            Err(SnapshotError::Truncated(_))
        ));
    }

    #[test]
    fn surfaces_a_row_count_mismatch() {
        // Declare 3 rows but provide 2.
        let mut rows = account_row("alice", 1, b"");
        rows.extend(account_row("bob", 2, b""));
        let bytes = container(&[header_section(), section(section_names::ACCOUNT, 3, &rows)]);

        let snapshot = SnapshotReader::new(&bytes).unwrap();
        let result: Result<Vec<_>, _> = snapshot.accounts().unwrap().collect();
        assert!(matches!(result, Err(SnapshotError::Decode { .. })));
    }

    #[test]
    fn surfaces_trailing_bytes() {
        // One declared row plus a stray byte the schema does not cover.
        let mut rows = account_row("alice", 1, b"");
        rows.push(0xAA);
        let bytes = container(&[header_section(), section(section_names::ACCOUNT, 1, &rows)]);

        let snapshot = SnapshotReader::new(&bytes).unwrap();
        let result: Result<Vec<_>, _> = snapshot.accounts().unwrap().collect();
        assert!(matches!(
            result,
            Err(SnapshotError::TrailingBytes { remaining: 1, .. })
        ));
    }

    #[test]
    fn decodes_an_interleaved_contract_tables_section() {
        let table = TableIdRow {
            code: "eosio.token".parse().unwrap(),
            scope: "protonnz".parse().unwrap(),
            table: "accounts".parse().unwrap(),
            payer: "protonnz".parse().unwrap(),
            count: 2,
        };
        let mut rows = Vec::new();
        rows.extend(table.code.pack().unwrap());
        rows.extend(table.scope.pack().unwrap());
        rows.extend(table.table.pack().unwrap());
        rows.extend(table.payer.pack().unwrap());
        rows.extend(table.count.to_le_bytes());
        // key_value: 1 row {primary_key, payer, value}
        rows.push(1);
        rows.extend(7u64.to_le_bytes());
        rows.extend(table.payer.pack().unwrap());
        rows.extend([2, 0xBE, 0xEF]); // 2-byte value
        // idx64: 1 row {primary_key, payer, secondary_key}
        rows.push(1);
        rows.extend(7u64.to_le_bytes());
        rows.extend(table.payer.pack().unwrap());
        rows.extend(99u64.to_le_bytes());
        // idx128, idx256, idx_double, idx_long_double: empty
        rows.extend([0, 0, 0, 0]);
        // 1 table row + 6 count rows + 2 data rows
        let bytes = container(&[
            header_section(),
            section(section_names::CONTRACT_TABLES, 9, &rows),
        ]);

        let snapshot = SnapshotReader::new(&bytes).unwrap();
        let tables: Vec<_> = snapshot
            .contract_tables()
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].table, table);
        assert_eq!(tables[0].key_values.len(), 1);
        assert_eq!(tables[0].key_values[0].primary_key, 7);
        assert_eq!(tables[0].key_values[0].value.0, vec![0xBE, 0xEF]);
        assert_eq!(tables[0].idx64.len(), 1);
        assert_eq!(tables[0].idx64[0].secondary_key, 99);
        assert!(tables[0].idx128.is_empty());
    }
}
