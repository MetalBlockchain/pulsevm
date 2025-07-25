use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::Name;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct ResourceLimits {
    pub owner: Name,
    pub net_weight: i64,
    pub cpu_weight: i64,
    pub ram_bytes: i64,
}

impl ResourceLimits {
    pub fn new(owner: Name, net_weight: i64, cpu_weight: i64, ram_bytes: i64) -> Self {
        ResourceLimits {
            owner,
            net_weight,
            cpu_weight,
            ram_bytes,
        }
    }
}

impl ChainbaseObject for ResourceLimits {
    type PrimaryKey = Name;

    fn primary_key(&self) -> Vec<u8> {
        ResourceLimits::primary_key_to_bytes(self.owner)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.as_u64().to_be_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "resource_limits"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
}
