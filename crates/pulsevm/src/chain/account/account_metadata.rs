use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::{Id, Name};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct AccountMetadata {
    pub name: Name,
    pub recv_sequence: u64,
    pub auth_sequence: u64,
    pub code_sequence: u64,
    pub abi_sequence: u64,
    pub code_hash: Id,
    pub last_code_update: u64,
    pub priviliged: bool,
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
            priviliged: false,
            vm_type: 0,
            vm_version: 0,
        }
    }

    pub fn is_privileged(&self) -> bool {
        self.priviliged
    }
}

impl Serialize for AccountMetadata {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.name.serialize(bytes);
        self.recv_sequence.serialize(bytes);
        self.auth_sequence.serialize(bytes);
        self.code_sequence.serialize(bytes);
        self.abi_sequence.serialize(bytes);
        self.code_hash.serialize(bytes);
        self.last_code_update.serialize(bytes);
        self.priviliged.serialize(bytes);
        self.vm_type.serialize(bytes);
        self.vm_version.serialize(bytes);
    }
}

impl Deserialize for AccountMetadata {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let name = Name::deserialize(data, pos)?;
        let recv_sequence = u64::deserialize(data, pos)?;
        let auth_sequence = u64::deserialize(data, pos)?;
        let code_sequence = u64::deserialize(data, pos)?;
        let abi_sequence = u64::deserialize(data, pos)?;
        let code_hash = Id::deserialize(data, pos)?;
        let last_code_update = u64::deserialize(data, pos)?;
        let priviliged = bool::deserialize(data, pos)?;
        let vm_type = u8::deserialize(data, pos)?;
        let vm_version = u8::deserialize(data, pos)?;

        Ok(AccountMetadata {
            name,
            recv_sequence,
            auth_sequence,
            code_sequence,
            abi_sequence,
            code_hash,
            last_code_update,
            priviliged,
            vm_type,
            vm_version,
        })
    }
}

impl<'a> ChainbaseObject<'a> for AccountMetadata {
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
