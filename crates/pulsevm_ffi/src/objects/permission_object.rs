use pulsevm_error::ChainError;

use crate::{Database, PermissionObject};

impl PermissionObject {
    pub fn satisfies(&self, other: &PermissionObject, db: &mut Database) -> Result<bool, ChainError> {
        Ok(true) // TODO: Fix this
    }
}