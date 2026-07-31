use pulsevm_crypto::Digest;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::{Write, WriteError};
use serde::Serialize;

use crate::chain::transaction::{PackedTransaction, TransactionReceiptHeader};

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Serialize)]
pub struct TransactionReceipt {
    #[serde(flatten)]
    header: TransactionReceiptHeader,
    #[serde(skip)]
    trx_variant: u8, // always 1 for now
    trx: PackedTransaction,
}

impl TransactionReceipt {
    pub fn new(header: TransactionReceiptHeader, trx: PackedTransaction) -> Self {
        TransactionReceipt {
            header,
            trx_variant: 1,
            trx,
        }
    }

    pub fn trx(&self) -> &PackedTransaction {
        &self.trx
    }

    /// Block-recorded CPU (µs) for this transaction — used to bill the recorded
    /// usage on replay instead of re-measuring.
    pub fn cpu_usage_us(&self) -> u32 {
        self.header.cpu_usage_us
    }

    /// Block-recorded NET (words) for this transaction.
    pub fn net_usage_words(&self) -> u32 {
        self.header.net_usage_words.0
    }

    pub fn digest(&self) -> Result<Digest, WriteError> {
        Ok(Digest::hash(self.pack()?))
    }
}
