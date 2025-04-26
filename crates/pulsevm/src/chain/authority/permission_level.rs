use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::Name;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PermissionLevel {
    actor: Name,
    permission: Name,
}

impl PermissionLevel {
    pub fn new(actor: Name, permission: Name) -> Self {
        PermissionLevel { actor, permission }
    }

    pub fn actor(&self) -> &Name {
        &self.actor
    }

    pub fn permission(&self) -> &Name {
        &self.permission
    }
}

impl Serialize for PermissionLevel {
    fn serialize(
        &self,
        bytes: &mut Vec<u8>,
    ) {
        self.actor.serialize(bytes);
        self.permission.serialize(bytes);
    }
}

impl Deserialize for PermissionLevel {
    fn deserialize(
        data: &[u8],
        pos: &mut usize
    ) -> Result<Self, pulsevm_serialization::ReadError> {
        let actor = Name::deserialize(data, pos)?;
        let permission = Name::deserialize(data, pos)?;
        Ok(PermissionLevel { actor, permission })
    }
}

impl<'a> ChainbaseObject<'a> for PermissionLevel {
    type PrimaryKey = PermissionLevel;
    
    fn primary_key(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        self.actor.serialize(&mut bytes);
        self.permission.serialize(&mut bytes);
        bytes
    }

    fn primary_key_as_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.primary_key()
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }

    fn table_name() -> &'static str {
        "permission_level"
    }
}