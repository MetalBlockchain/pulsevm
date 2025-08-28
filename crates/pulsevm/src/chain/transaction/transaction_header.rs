use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::VarUint32;
use pulsevm_time::TimePointSec;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes, Serialize)]
pub struct TransactionHeader {
    pub expiration: TimePointSec,
    pub ref_block_num: u16,
    pub ref_block_prefix: u32,
    pub max_net_usage_words: VarUint32,
    pub max_cpu_usage: u8,
    pub delay_sec: VarUint32,
}

impl TransactionHeader {
    pub fn new(
            expiration: TimePointSec,
            ref_block_num: u16,
            ref_block_prefix: u32,
            max_net_usage_words: VarUint32,
            max_cpu_usage: u8,
            delay_sec: VarUint32,
    ) -> Self {
        Self {
            expiration,
            ref_block_num,
            ref_block_prefix,
            max_net_usage_words,
            max_cpu_usage,
            delay_sec,
        }
    }

    pub fn expiration(&self) -> &TimePointSec {
        &self.expiration
    }

    pub fn max_net_usage_words(&self) -> VarUint32 {
        self.max_net_usage_words
    }

    pub fn max_cpu_usage(&self) -> u8 {
        self.max_cpu_usage
    }

    pub fn delay_sec(&self) -> VarUint32 {
        self.delay_sec
    }
}
