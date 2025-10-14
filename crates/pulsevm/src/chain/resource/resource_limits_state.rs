use pulsevm_chainbase::{ChainbaseObject, SecondaryKey};
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::UsageAccumulator;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct ResourceLimitsState {
    pub average_block_net_usage: UsageAccumulator,
    pub average_block_cpu_usage: UsageAccumulator,

    pub pending_net_usage: u64,
    pub pending_cpu_usage: u64,

    pub total_net_weight: u64,
    pub total_cpu_weight: u64,
    pub total_ram_bytes: u64,
    
    pub virtual_net_limit: u64,
    pub virtual_cpu_limit: u64,
}

impl ChainbaseObject for ResourceLimitsState {
    type PrimaryKey = u64;

    fn primary_key(&self) -> Vec<u8> {
        ResourceLimitsState::primary_key_to_bytes(0)
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.to_le_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "resource_limits_state"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
}
