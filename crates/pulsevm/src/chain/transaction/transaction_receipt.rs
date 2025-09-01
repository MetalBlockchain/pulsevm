use pulsevm_crypto::Digest;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::{NumBytes, Read, VarUint32, Write, WriteError};
use serde::Serialize;

use crate::chain::{Id, PackedTransaction, TransactionStatus};

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Serialize)]
pub struct TransactionReceipt {
    status: TransactionStatus,
    cpu_usage_us: u32,
    net_usage_words: VarUint32,
    trx_variant: u8, // always 1 for now
    trx: PackedTransaction,
}

impl TransactionReceipt {
    pub fn new(
        status: TransactionStatus,
        cpu_usage_us: u32,
        net_usage_words: VarUint32,
        trx: PackedTransaction,
    ) -> Self {
        TransactionReceipt {
            status,
            cpu_usage_us,
            net_usage_words,
            trx_variant: 1,
            trx,
        }
    }

    pub fn status(&self) -> &TransactionStatus {
        &self.status
    }

    pub fn cpu_usage_us(&self) -> u32 {
        self.cpu_usage_us
    }

    pub fn net_usage_words(&self) -> &VarUint32 {
        &self.net_usage_words
    }

    pub fn trx(&self) -> &PackedTransaction {
        &self.trx
    }

    pub fn digest(&self) -> Result<Digest, WriteError> {
        Ok(Digest::hash(self.pack()?))
    }
}
