use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::{Id, genesis::ChainConfig};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct GlobalPropertyObject {
    pub chain_id: Id,
    pub configuration: ChainConfig,
}

impl Serialize for GlobalPropertyObject {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.chain_id.serialize(bytes);
        self.configuration.serialize(bytes);
    }
}

impl Deserialize for GlobalPropertyObject {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let chain_id = Id::deserialize(data, pos)?;
        let configuration = ChainConfig::deserialize(data, pos)?;
        Ok(GlobalPropertyObject {
            chain_id,
            configuration,
        })
    }
}

impl ChainbaseObject for GlobalPropertyObject {
    type PrimaryKey = u64;

    fn primary_key(&self) -> Vec<u8> {
        GlobalPropertyObject::primary_key_to_bytes(0)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.to_be_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "gpo"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
}
