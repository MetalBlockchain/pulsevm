use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::{Id, Name};

use super::Authority;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Permission {
    id: Id,
    parent_id: Id,
    pub owner: Name,
    pub name: Name,
    pub authority: Authority,
}

impl Permission {
    pub fn new(
        id: Id,
        parent_id: Id,
        owner: Name,
        name: Name,
        authority: Authority,
    ) -> Self {
        Permission { id, parent_id, owner, name, authority }
    }

    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn parent_id(&self) -> &Id {
        &self.parent_id
    }
}

impl Serialize for Permission {
    fn serialize(
        &self,
        bytes: &mut Vec<u8>,
    ) {
        self.id.serialize(bytes);
        self.parent_id.serialize(bytes);
        self.owner.serialize(bytes);
        self.name.serialize(bytes);
        self.authority.serialize(bytes);
    }
}

impl Deserialize for Permission {
    fn deserialize(
        data: &[u8],
        pos: &mut usize
    ) -> Result<Self, pulsevm_serialization::ReadError> {
        let id = Id::deserialize(data, pos)?;
        let parent_id = Id::deserialize(data, pos)?;
        let owner = Name::deserialize(data, pos)?;
        let name = Name::deserialize(data, pos)?;
        let authority = Authority::deserialize(data, pos)?;
        Ok(Permission { id, parent_id, owner, name, authority })
    }
}

impl<'a> ChainbaseObject<'a> for Permission {
    type PrimaryKey = (&'a Name, &'a Name);

    fn primary_key(&self) -> Vec<u8> {
        Permission::primary_key_as_bytes((&self.owner, &self.name))
    }

    fn primary_key_as_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        let mut bytes = Vec::new();
        key.0.serialize(&mut bytes);
        key.1.serialize(&mut bytes);
        bytes
    }

    fn table_name() -> &'static str {
        "permission"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
}