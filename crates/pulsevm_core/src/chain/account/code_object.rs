use std::sync::Arc;

use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::id::Id;

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct CodeObject {
    pub code_hash: Id,
    pub code: Arc<Vec<u8>>,
    pub code_ref_count: u64,
    pub first_block_used: u32,
    pub vm_type: u8,
    pub vm_version: u8,
}

impl ChainbaseObject for CodeObject {
    type PrimaryKey = Id;

    fn primary_key(&self) -> Vec<u8> {
        CodeObject::primary_key_to_bytes(self.code_hash)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.as_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "code_object"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
}
