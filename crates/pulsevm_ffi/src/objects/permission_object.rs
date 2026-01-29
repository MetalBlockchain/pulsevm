use pulsevm_error::ChainError;

use crate::{Database, PermissionObject};

impl PermissionObject {
    pub fn satisfies(&self, other: &PermissionObject, db: &mut Database) -> Result<bool, ChainError> {
        Ok(true) // TODO: Fix this
    }
}

impl PartialEq for PermissionObject {
    fn eq(&self, other: &Self) -> bool {
        self.get_id() == other.get_id()
    }
}

impl Eq for PermissionObject {}