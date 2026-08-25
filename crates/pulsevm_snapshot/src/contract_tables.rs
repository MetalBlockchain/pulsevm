//! The `contract_tables` section is the one section that is not a plain row
//! list. The writer emits, per contract table:
//!
//! ```text
//! table_id_object row
//! for each index family (key_value, idx64, idx128, idx256, idx_double, idx_long_double):
//!     varuint row-count
//!     that many data rows
//! ```
//!
//! and the section's declared row count covers *all* of those physical rows.

use pulsevm_serialization::VarUint32;

use crate::{
    error::SnapshotError,
    reader::SectionReader,
    rows::{
        Index64Row,
        Index128Row,
        Index256Row,
        IndexDoubleRow,
        IndexLongDoubleRow,
        KeyValueRow,
        TableIdRow,
    },
};

/// One contract table with all of its rows across every index family.
#[derive(Debug, Clone)]
pub struct TableSnapshot {
    pub table: TableIdRow,
    pub key_values: Vec<KeyValueRow>,
    pub idx64: Vec<Index64Row>,
    pub idx128: Vec<Index128Row>,
    pub idx256: Vec<Index256Row>,
    pub idx_double: Vec<IndexDoubleRow>,
    pub idx_long_double: Vec<IndexLongDoubleRow>,
}

/// Streaming reader for the `contract_tables` section: one [`TableSnapshot`]
/// at a time, so the caller never has to hold every table's rows in memory at
/// once.
pub struct ContractTablesReader<'a> {
    section: SectionReader<'a>,
    failed: bool,
}

impl<'a> ContractTablesReader<'a> {
    pub(crate) fn new(section: SectionReader<'a>) -> Self {
        ContractTablesReader {
            section,
            failed: false,
        }
    }

    fn read_index_rows<T: pulsevm_serialization::Read>(&mut self) -> Result<Vec<T>, SnapshotError> {
        let count = self.section.read_row::<VarUint32>()?.0 as usize;
        let mut rows = Vec::with_capacity(count.min(1 << 20));
        for _ in 0..count {
            rows.push(self.section.read_row::<T>()?);
        }
        Ok(rows)
    }

    /// Decode the next table, or `Ok(None)` after the last table once the
    /// section has verified as byte-exactly consumed.
    pub fn next_table(&mut self) -> Result<Option<TableSnapshot>, SnapshotError> {
        if self.section.rows_read() == self.section.row_count() {
            self.section.finish()?;
            return Ok(None);
        }
        let table = self.section.read_row::<TableIdRow>()?;
        Ok(Some(TableSnapshot {
            table,
            key_values: self.read_index_rows()?,
            idx64: self.read_index_rows()?,
            idx128: self.read_index_rows()?,
            idx256: self.read_index_rows()?,
            idx_double: self.read_index_rows()?,
            idx_long_double: self.read_index_rows()?,
        }))
    }
}

impl<'a> Iterator for ContractTablesReader<'a> {
    type Item = Result<TableSnapshot, SnapshotError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        match self.next_table() {
            Ok(Some(table)) => Some(Ok(table)),
            Ok(None) => None,
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }
}
