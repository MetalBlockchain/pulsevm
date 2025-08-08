use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_time::TimePointSec;
use serde::Serialize;

use crate::chain::Id;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes, Serialize)]
pub struct TransactionHeader {
    pub expiration: TimePointSec,
    pub max_net_usage_words: u32,
    pub max_cpu_usage: u32,
    pub blockchain_id: Id, // ID of the chain on which this transaction exists (prevents replay attacks)
}

impl TransactionHeader {
    pub fn new(
        expiration: TimePointSec,
        max_net_usage_words: u32,
        max_cpu_usage: u32,
        blockchain_id: Id,
    ) -> Self {
        Self {
            expiration,
            max_net_usage_words,
            max_cpu_usage,
            blockchain_id,
        }
    }

    pub fn expiration(&self) -> &TimePointSec {
        &self.expiration
    }

    pub fn max_net_usage_words(&self) -> u32 {
        self.max_net_usage_words
    }

    pub fn max_cpu_usage(&self) -> u32 {
        self.max_cpu_usage
    }

    pub fn blockchain_id(&self) -> &Id {
        &self.blockchain_id
    }
}
