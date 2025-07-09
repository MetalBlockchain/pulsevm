use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::Id;

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct CodeObject {
    pub code_hash: Id,
    pub code: Vec<u8>,
    pub code_ref_count: u64,
    pub first_block_used: u32,
    pub vm_type: u8,
    pub vm_version: u8,
}

impl Serialize for CodeObject {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.code_hash.serialize(bytes);
        self.code.serialize(bytes);
        self.code_ref_count.serialize(bytes);
        self.first_block_used.serialize(bytes);
        self.vm_type.serialize(bytes);
        self.vm_version.serialize(bytes);
    }
}

impl Deserialize for CodeObject {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let code_hash = Id::deserialize(data, pos)?;
        let code = Vec::<u8>::deserialize(data, pos)?;
        let code_ref_count = u64::deserialize(data, pos)?;
        let first_block_used = u32::deserialize(data, pos)?;
        let vm_type = u8::deserialize(data, pos)?;
        let vm_version = u8::deserialize(data, pos)?;

        Ok(CodeObject {
            code_hash,
            code,
            code_ref_count,
            first_block_used,
            vm_type,
            vm_version,
        })
    }
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
