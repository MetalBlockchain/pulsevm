use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::config::BillableSize;

use super::permission_level::PermissionLevel;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct PermissionLevelWeight {
    permission: PermissionLevel,
    weight: u16,
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

impl Serialize for PermissionLevelWeight {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.permission.serialize(bytes);
        self.weight.serialize(bytes);
    }
}

impl Deserialize for PermissionLevelWeight {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let permission = PermissionLevel::deserialize(data, pos)?;
        let weight = u16::deserialize(data, pos)?;
        Ok(PermissionLevelWeight { permission, weight })
    }
}

impl BillableSize for PermissionLevelWeight {
    fn billable_size() -> u64 {
        24
    }
}
