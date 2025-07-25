use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{Id, genesis::ChainConfig};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct GlobalPropertyObject {
    pub chain_id: Id,
    pub configuration: ChainConfig,
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
