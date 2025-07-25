use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{Id, Name};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct AccountMetadata {
    pub name: Name,
    pub recv_sequence: u64,
    pub auth_sequence: u64,
    pub code_sequence: u32,
    pub abi_sequence: u32,
    pub code_hash: Id,
    pub last_code_update: u64,
    pub privileged: bool,
    pub vm_type: u8,
    pub vm_version: u8,
}

impl AccountMetadata {
    pub fn new(name: Name) -> Self {
        AccountMetadata {
            name,
            recv_sequence: 0,
            auth_sequence: 0,
            code_sequence: 0,
            abi_sequence: 0,
            code_hash: Id::default(),
            last_code_update: 0,
            privileged: false,
            vm_type: 0,
            vm_version: 0,
        }
    }

    pub fn is_privileged(&self) -> bool {
        self.privileged
    }
}

impl ChainbaseObject for AccountMetadata {
    type PrimaryKey = Name;

    fn primary_key(&self) -> Vec<u8> {
        AccountMetadata::primary_key_to_bytes(self.name)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.as_u64().to_be_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "account_metadata"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
}
