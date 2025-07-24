use pulsevm_chainbase::{ChainbaseObject, SecondaryIndex, SecondaryKey};
use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::{Name, config::BillableSize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct KeyValue {
    pub id: u64,
    pub table_id: u64,
    pub primary_key: u64,
    pub payer: Name,
    pub value: Vec<u8>,
}

impl KeyValue {
    pub fn new(id: u64, table_id: u64, primary_key: u64, payer: Name, value: Vec<u8>) -> Self {
        KeyValue {
            id,
            table_id,
            primary_key,
            payer,
            value,
        }
    }
}

impl BillableSize for KeyValue {
    fn billable_size() -> u64 {
        32 + 8 + 4 + 64
    }
}

impl Serialize for KeyValue {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.id.serialize(bytes);
        self.table_id.serialize(bytes);
        self.primary_key.serialize(bytes);
        self.payer.serialize(bytes);
        self.value.serialize(bytes);
    }
}

impl Deserialize for KeyValue {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let id = u64::deserialize(data, pos)?;
        let table_id = u64::deserialize(data, pos)?;
        let primary_key = u64::deserialize(data, pos)?;
        let payer = Name::deserialize(data, pos)?;
        let value = Vec::<u8>::deserialize(data, pos)?;

        Ok(KeyValue {
            id,
            table_id,
            primary_key,
            payer,
            value,
        })
    }
}

impl ChainbaseObject for KeyValue {
    type PrimaryKey = u64;

    fn primary_key(&self) -> Vec<u8> {
        self.id.to_be_bytes().to_vec()
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.to_be_bytes().to_vec()
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
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&key.0.to_be_bytes());
        bytes.extend_from_slice(&key.1.to_be_bytes());
        bytes
    }

    fn index_name() -> &'static str {
        "key_value_by_scope_primary"
    }
}
