use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::Ratio;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct ElasticLimitParameters {
    pub target: u64,
    pub max: u64,
    pub periods: u32,
    pub max_multiplier: u32,
    pub contract_rate: Ratio<u64>,
    pub expand_rate: Ratio<u64>,
}
