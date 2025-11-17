use core::fmt;

use pulsevm_chainbase::{ChainbaseObject, SecondaryIndex, SecondaryKey};
use pulsevm_crypto::Bytes;
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{Name, config::BillableSize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct KeyValue {
    pub id: u64,
    pub table_id: u64,
    pub primary_key: u64,
    pub payer: Name,
    pub value: Bytes,
}

impl KeyValue {
    pub fn new(id: u64, table_id: u64, primary_key: u64, payer: Name, value: Bytes) -> Self {
        KeyValue {
            id,
            table_id,
            primary_key,
            payer,
            value,
        }
    }
}

impl fmt::Display for KeyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyValue {{ id: {}, table_id: {}, primary_key: {}, payer: {}, value: {:?} }}",
            self.id, self.table_id, self.primary_key, self.payer, self.value
        )
    }
}

impl BillableSize for KeyValue {
    fn billable_size() -> u64 {
        32 + 8 + 4 + 64
    }
}

impl ChainbaseObject for KeyValue {
    type PrimaryKey = u64;

    fn primary_key(&self) -> Vec<u8> {
        self.id.to_le_bytes().to_vec()
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.to_le_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "key_value"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![SecondaryKey {
            key: KeyValueByScopePrimaryIndex::secondary_key_as_bytes((
                self.table_id,
                self.primary_key,
            )),
            index_name: KeyValueByScopePrimaryIndex::index_name(),
        }]
    }
}

#[derive(Debug, Default)]
pub struct KeyValueByScopePrimaryIndex;

impl SecondaryIndex<KeyValue> for KeyValueByScopePrimaryIndex {
    type Key = (u64, u64);
    type Object = KeyValue;

    fn secondary_key(object: &KeyValue) -> Vec<u8> {
        KeyValueByScopePrimaryIndex::secondary_key_as_bytes((object.table_id, object.primary_key))
    }

    fn secondary_key_as_bytes(key: Self::Key) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&key.0.to_le_bytes());
        bytes.extend_from_slice(&key.1.to_le_bytes());
        bytes
    }

    fn index_name() -> &'static str {
        "key_value_by_scope_primary"
    }
}
