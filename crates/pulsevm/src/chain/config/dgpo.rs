use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_serialization::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct DynamicGlobalPropertyObject {
    pub global_action_sequence: u64,
}

impl DynamicGlobalPropertyObject {
    pub fn new(global_action_sequence: u64) -> Self {
        DynamicGlobalPropertyObject {
            global_action_sequence,
        }
    }
}

impl Serialize for DynamicGlobalPropertyObject {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.global_action_sequence.serialize(bytes);
    }
}

impl Deserialize for DynamicGlobalPropertyObject {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let global_action_sequence = u64::deserialize(data, pos)?;
        Ok(DynamicGlobalPropertyObject {
            global_action_sequence,
        })
    }
}

impl ChainbaseObject for DynamicGlobalPropertyObject {
    type PrimaryKey = u64;

    fn primary_key(&self) -> Vec<u8> {
        DynamicGlobalPropertyObject::primary_key_to_bytes(0)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.to_be_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "dgpo"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
}
