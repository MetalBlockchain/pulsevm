use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
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

impl ChainbaseObject for DynamicGlobalPropertyObject {
    type PrimaryKey = u64;

    fn primary_key(&self) -> Vec<u8> {
        DynamicGlobalPropertyObject::primary_key_to_bytes(0)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.to_le_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "dgpo"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
}
