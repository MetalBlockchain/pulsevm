use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;

use crate::chain::Name;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct ResourceLimits {
    pub owner: Name,
    pub pending: bool,
    pub net_weight: i64,
    pub cpu_weight: i64,
    pub ram_bytes: i64,
}

impl ResourceLimits {
    pub fn new(
        owner: Name,
        pending: bool,
        net_weight: i64,
        cpu_weight: i64,
        ram_bytes: i64,
    ) -> Self {
        ResourceLimits {
            owner,
            pending,
            net_weight,
            cpu_weight,
            ram_bytes,
        }
    }
}

impl ChainbaseObject for ResourceLimits {
    type PrimaryKey = (bool, Name);

    fn primary_key(&self) -> Vec<u8> {
        ResourceLimits::primary_key_to_bytes((self.pending, self.owner))
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.pack().unwrap()
    }

    fn table_name() -> &'static str {
        "resource_limits"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
}
