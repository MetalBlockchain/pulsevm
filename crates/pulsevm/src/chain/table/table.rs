use pulsevm_chainbase::{ChainbaseObject, SecondaryIndex, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::Name;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct Table {
    pub id: u64,
    pub code: Name,
    pub scope: Name,
    pub table: Name,
    pub payer: Name,
    pub count: u32,
}

impl Table {
    pub fn new(id: u64, code: Name, scope: Name, table: Name, payer: Name, count: u32) -> Self {
        Table {
            id,
            code,
            scope,
            table,
            payer,
            count,
        }
    }
}

impl ChainbaseObject for Table {
    type PrimaryKey = u16;

    fn primary_key(&self) -> Vec<u8> {
        self.id.to_be_bytes().to_vec()
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.to_be_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "table"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![SecondaryKey {
            key: TableByCodeScopeTableIndex::secondary_key_as_bytes((
                self.code.clone(),
                self.scope.clone(),
                self.table.clone(),
            )),
            index_name: TableByCodeScopeTableIndex::index_name(),
        }]
    }
}

#[derive(Debug, Default)]
pub struct TableByCodeScopeTableIndex;

impl SecondaryIndex<Table> for TableByCodeScopeTableIndex {
    type Key = (Name, Name, Name);
    type Object = Table;

    fn secondary_key(object: &Table) -> Vec<u8> {
        TableByCodeScopeTableIndex::secondary_key_as_bytes((
            object.code.clone(),
            object.scope.clone(),
            object.table.clone(),
        ))
    }

    fn secondary_key_as_bytes(key: Self::Key) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&key.0.as_u64().to_be_bytes());
        bytes.extend_from_slice(&key.1.as_u64().to_be_bytes());
        bytes.extend_from_slice(&key.2.as_u64().to_be_bytes());
        bytes
    }

    fn index_name() -> &'static str {
        "table_by_code_scope_table"
    }
}