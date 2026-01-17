use core::fmt;

use pulsevm_error::ChainError;
use pulsevm_ffi::Database;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::Serialize;

use crate::chain::{
    Name,
    config::{self, BillableSize, OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES},
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

    pub fn satisfies(&self, other: &Permission, db: &Database) -> Result<bool, ChainError> {
        // If the owners are not the same, this permission cannot satisfy other
        if self.owner != other.owner {
            return Ok(false);
        }

        // If this permission matches other, or is the immediate parent of other, then this permission satisfies other
        if self.id == other.id || self.id == other.parent {
            return Ok(true);
        }

        // Walk up other's parent tree, seeing if we find this permission. If so, this permission satisfies other
        let parent = db.find_permission(other.parent as i64)?;
        let mut parent = if parent.is_null() {
            None
        } else {
            unsafe { Some(&*parent) }
        };

        while let Some(parent_obj) = parent {
            if self.id == parent_obj.get_id() as u64 {
                return Ok(true);
            } else if parent_obj.get_id() == 0 {
                return Ok(false);
            }
            let other_parent = db.find_permission(parent_obj.get_parent_id() as i64)?;
            parent = if other_parent.is_null() {
                None
            } else {
                unsafe { Some(&*other_parent) }
            };
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

impl BillableSize for Permission {
    fn billable_size() -> u64 {
        let overhead: u64 = 5 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
        let value = (config::billable_size_v::<Authority>() + 64) + overhead;
        value
    }
}
