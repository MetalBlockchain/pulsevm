use core::fmt;

use pulsevm_chainbase::{ChainbaseObject, SecondaryIndex, SecondaryKey, UndoSession};
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;
use serde::Serialize;

use crate::{
    chain::{
        Name,
        config::{self, BillableSize, OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES},
    },
    error::ChainError,
};

use super::authority::Authority;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes, Serialize)]
pub struct Permission {
    pub id: u64,
    pub parent: u64,
    pub owner: Name,
    pub name: Name,
    pub authority: Authority,
}

impl Permission {
    pub fn new(id: u64, parent: u64, owner: Name, name: Name, authority: Authority) -> Self {
        Permission {
            id,
            parent,
            owner,
            name,
            authority,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn satisfies(
        &self,
        other: &Permission,
        session: &mut UndoSession,
    ) -> Result<bool, ChainError> {
        // If the owners are not the same, this permission cannot satisfy other
        if self.owner != other.owner {
            return Ok(false);
        }

        // If this permission matches other, or is the immediate parent of other, then this permission satisfies other
        if self.id == other.id || self.id == other.parent {
            return Ok(true);
        }

        // Walk up other's parent tree, seeing if we find this permission. If so, this permission satisfies other
        let mut parent = session.find::<Permission>(other.parent)?;

        while let Some(parent_obj) = parent {
            if self.id == parent_obj.id {
                return Ok(true);
            } else if parent_obj.id == 0 {
                return Ok(false);
            }
            parent = session.find::<Permission>(parent_obj.parent)?;
        }

        // This permission is not a parent of other, and so does not satisfy other
        Ok(false)
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}@{}", self.owner, self.name)
    }
}

impl ChainbaseObject for Permission {
    type PrimaryKey = u64;

    fn primary_key(&self) -> Vec<u8> {
        Permission::primary_key_to_bytes(self.id)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.to_le_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "permission"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![
            SecondaryKey {
                key: PermissionByOwnerIndex::secondary_key_as_bytes((self.owner, self.name)),
                index_name: PermissionByOwnerIndex::index_name(),
            },
            SecondaryKey {
                key: PermissionByParentIndex::secondary_key_as_bytes((self.parent, self.id)),
                index_name: PermissionByParentIndex::index_name(),
            },
        ]
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

#[derive(Debug, Default)]
pub struct PermissionByParentIndex;

impl SecondaryIndex<Permission> for PermissionByParentIndex {
    type Key = (u64, u64);
    type Object = Permission;

    fn secondary_key(object: &Permission) -> Vec<u8> {
        PermissionByParentIndex::secondary_key_as_bytes((object.parent, object.id))
    }

    fn secondary_key_as_bytes(key: Self::Key) -> Vec<u8> {
        let bytes = key.pack().unwrap();
        bytes
    }

    fn index_name() -> &'static str {
        "permission_by_parent"
    }
}

impl BillableSize for Permission {
    fn billable_size() -> u64 {
        let overhead: u64 = 5 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
        let value = (config::billable_size_v::<Authority>() + 64) + overhead;
        value
    }
}
