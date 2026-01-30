use pulsevm_billable_size::{BillableSize, billable_size_v};
use pulsevm_constants::OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES;
use pulsevm_error::ChainError;

use crate::{Database, PermissionObject, bridge::ffi::CxxSharedAuthority};

impl PermissionObject {
    pub fn satisfies(&self, other: &PermissionObject, db: &Database) -> Result<bool, ChainError> {
        db.permission_satisfies_other_permission(self, other)
    }
}

impl PartialEq for PermissionObject {
    fn eq(&self, other: &Self) -> bool {
        self.get_id() == other.get_id()
    }
}

impl Eq for PermissionObject {}

impl BillableSize for PermissionObject {
    const OVERHEAD: u64 = 5 * OVERHEAD_PER_ROW_PER_INDEX_RAM_BYTES as u64;
    const VALUE: u64 = (billable_size_v::<CxxSharedAuthority>() + 64) + PermissionObject::OVERHEAD;
}