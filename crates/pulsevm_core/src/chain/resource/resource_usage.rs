use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{name::Name, utils::UsageAccumulator};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct ResourceUsage {
    pub owner: Name,

    pub cpu_usage: UsageAccumulator,
    pub net_usage: UsageAccumulator,

    pub ram_usage: u64,
}

impl ResourceUsage {
    pub fn new(
        owner: Name,
        cpu_usage: UsageAccumulator,
        net_usage: UsageAccumulator,
        ram_usage: u64,
    ) -> Self {
        ResourceUsage {
            owner,
            cpu_usage,
            net_usage,
            ram_usage,
        }
    }
}

impl ChainbaseObject for ResourceUsage {
    type PrimaryKey = Name;

    fn primary_key(&self) -> Vec<u8> {
        ResourceUsage::primary_key_to_bytes(self.owner)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.as_u64().to_le_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "resource_usage"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
}
