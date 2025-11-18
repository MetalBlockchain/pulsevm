use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::Serialize;

use crate::chain::config::BillableSize;

use super::permission_level::PermissionLevel;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes, Serialize)]
pub struct PermissionLevelWeight {
    pub permission: PermissionLevel,
    pub weight: u16,
}

impl PermissionLevelWeight {
    pub fn new(permission: PermissionLevel, weight: u16) -> Self {
        PermissionLevelWeight { permission, weight }
    }

    pub fn permission(&self) -> &PermissionLevel {
        &self.permission
    }

    pub fn weight(&self) -> u16 {
        self.weight
    }
}

impl BillableSize for PermissionLevelWeight {
    fn billable_size() -> u64 {
        24
    }
}
