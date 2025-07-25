use pulsevm_chainbase::{ChainbaseObject, SecondaryIndex, SecondaryKey, UndoSession};
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;

use crate::chain::{
    Name,
    config::{self, BillableSize, OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES},
};

use super::authority::Authority;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct Permission {
    id: u64,
    parent_id: u64,
    pub owner: Name,
    pub name: Name,
    pub authority: Authority,
}

impl Permission {
    pub fn new(id: u64, parent_id: u64, owner: Name, name: Name, authority: Authority) -> Self {
        Permission {
            id,
            parent_id,
            owner,
            name,
            authority,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn parent_id(&self) -> u64 {
        self.parent_id
    }

    pub fn satisfies(
        &self,
        other: &Permission,
        session: &mut UndoSession,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // If the owners are not the same, this permission cannot satisfy other
        if self.owner != other.owner {
            return Ok(false);
        }

        // If this permission matches other, or is the immediate parent of other, then this permission satisfies other
        if self.id == other.id || self.id == other.parent_id {
            return Ok(true);
        }

        // Walk up other's parent tree, seeing if we find this permission. If so, this permission satisfies other
        let mut parent = session.find::<Permission>(other.parent_id)?;
        while parent.is_some() {
            let parent_obj = parent.unwrap();
            if self.id == parent_obj.parent_id {
                return Ok(true);
            } else if parent_obj.id == 0 {
                return Ok(false);
            }
            parent = session.find::<Permission>(parent_obj.parent_id)?;
        }

        // This permission is not a parent of other, and so does not satisfy other
        Ok(false)
    }
}

impl ChainbaseObject for Permission {
    type PrimaryKey = u64;

    fn primary_key(&self) -> Vec<u8> {
        Permission::primary_key_to_bytes(self.id)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.to_be_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "permission"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![SecondaryKey {
            key: PermissionByOwnerIndex::secondary_key_as_bytes((self.owner, self.name)),
            index_name: PermissionByOwnerIndex::index_name(),
        }]
    }
}

#[derive(Debug, Default)]
pub struct PermissionByOwnerIndex;

impl SecondaryIndex<Permission> for PermissionByOwnerIndex {
    type Key = (Name, Name);
    type Object = Permission;

    fn secondary_key(object: &Permission) -> Vec<u8> {
        PermissionByOwnerIndex::secondary_key_as_bytes((object.owner, object.name))
    }

    fn secondary_key_as_bytes(key: Self::Key) -> Vec<u8> {
        let bytes = key.pack().unwrap();
        bytes
    }

    fn index_name() -> &'static str {
        "permission_by_owner"
    }
}

impl BillableSize for Permission {
    fn billable_size() -> u64 {
        let overhead: u64 = 5 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
        let value = (config::billable_size_v::<Authority>() + 64) + overhead;
        value
    }
}
