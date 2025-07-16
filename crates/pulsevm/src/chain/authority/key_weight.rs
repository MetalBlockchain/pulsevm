use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::{PublicKey, config::BillableSize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct KeyWeight {
    key: PublicKey,
    weight: u16,
}

impl KeyWeight {
    pub fn new(key: PublicKey, weight: u16) -> Self {
        KeyWeight { key, weight }
    }

    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    pub fn weight(&self) -> u16 {
        self.weight
    }
}

impl Serialize for KeyWeight {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.key.serialize(bytes);
        self.weight.serialize(bytes);
    }
}

impl Deserialize for KeyWeight {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let key = PublicKey::deserialize(data, pos)?;
        let weight = u16::deserialize(data, pos)?;
        Ok(KeyWeight { key, weight })
    }
}

impl BillableSize for KeyWeight {
    fn billable_size() -> u64 {
        8
    }
}
