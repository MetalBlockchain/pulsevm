use pulsevm_constants::{ACCOUNT_CPU_USAGE_AVERAGE_WINDOW_MS, ACCOUNT_NET_USAGE_AVERAGE_WINDOW_MS, BLOCK_CPU_USAGE_AVERAGE_WINDOW_MS, BLOCK_INTERVAL_MS, BLOCK_SIZE_AVERAGE_WINDOW_MS, DEFAULT_MAX_BLOCK_CPU_USAGE, DEFAULT_MAX_BLOCK_NET_USAGE, DEFAULT_TARGET_BLOCK_CPU_USAGE_PCT, DEFAULT_TARGET_BLOCK_NET_USAGE_PCT};
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::{
    config::{
        eos_percent,
    },
    resource::ElasticLimitParameters,
    utils::Ratio,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct ResourceLimitsConfig {
    pub cpu_limit_parameters: ElasticLimitParameters,
    pub net_limit_parameters: ElasticLimitParameters,

    pub account_cpu_usage_average_window: u32,
    pub account_net_usage_average_window: u32,
}

impl Default for ResourceLimitsConfig {
    fn default() -> Self {
        ResourceLimitsConfig {
            cpu_limit_parameters: ElasticLimitParameters {
                target: eos_percent(DEFAULT_MAX_BLOCK_CPU_USAGE as u64, DEFAULT_TARGET_BLOCK_CPU_USAGE_PCT),
                max: DEFAULT_MAX_BLOCK_CPU_USAGE as u64,
                periods: BLOCK_CPU_USAGE_AVERAGE_WINDOW_MS / BLOCK_INTERVAL_MS,
                max_multiplier: 1000,
                contract_rate: Ratio {
                    numerator: 99,
                    denominator: 100,
                },
                expand_rate: Ratio {
                    numerator: 1000,
                    denominator: 999,
                },
            },
            net_limit_parameters: ElasticLimitParameters {
                target: eos_percent(DEFAULT_MAX_BLOCK_NET_USAGE as u64, DEFAULT_TARGET_BLOCK_NET_USAGE_PCT),
                max: DEFAULT_MAX_BLOCK_NET_USAGE as u64,
                periods: BLOCK_SIZE_AVERAGE_WINDOW_MS / BLOCK_INTERVAL_MS,
                max_multiplier: 1000,
                contract_rate: Ratio {
                    numerator: 99,
                    denominator: 100,
                },
                expand_rate: Ratio {
                    numerator: 1000,
                    denominator: 999,
                },
            },
            account_cpu_usage_average_window: ACCOUNT_CPU_USAGE_AVERAGE_WINDOW_MS / BLOCK_INTERVAL_MS,
            account_net_usage_average_window: ACCOUNT_NET_USAGE_AVERAGE_WINDOW_MS / BLOCK_INTERVAL_MS,
        }
    }
}
