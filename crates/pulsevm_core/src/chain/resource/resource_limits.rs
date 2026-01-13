use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;

use crate::chain::Name;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct ResourceLimits {
    pub id: u64,
    pub owner: Name,
    pub pending: bool,
    pub net_weight: i64,
    pub cpu_weight: i64,
    pub ram_bytes: i64,
}

impl ResourceLimits {
    pub fn new(
        id: u64,
        owner: Name,
        pending: bool,
        net_weight: i64,
        cpu_weight: i64,
        ram_bytes: i64,
    ) -> Self {
        ResourceLimits {
            id,
            owner,
            pending,
            net_weight,
            cpu_weight,
            ram_bytes,
        }
    }
}
