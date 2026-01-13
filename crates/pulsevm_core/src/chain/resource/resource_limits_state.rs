use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::utils::UsageAccumulator;

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
