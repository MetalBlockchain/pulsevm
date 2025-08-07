use pulsevm_crypto::Digest;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::{Write, WriteError};
use serde::Serialize;

use crate::chain::{Id, TransactionStatus};

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Serialize)]
pub struct TransactionReceipt {
    status: TransactionStatus,
    cpu_usage_us: u32,
    net_usage_words: u32,
    trx_id: Id,
}

impl TransactionReceipt {
    pub fn new(
        status: TransactionStatus,
        cpu_usage_us: u32,
        net_usage_words: u32,
        trx_id: Id,
    ) -> Self {
        TransactionReceipt {
            status,
            cpu_usage_us,
            net_usage_words,
            trx_id,
        }
    }

    pub fn digest(&self) -> Result<Digest, WriteError> {
        let serialized = self.pack()?;
        Ok(Digest::hash(serialized))
    }
}