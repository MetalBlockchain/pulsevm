use pulsevm_crypto::Digest;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::{NumBytes, Read, VarUint32, Write, WriteError};
use serde::Serialize;
use tungstenite::http::header;

use crate::chain::{Id, PackedTransaction, TransactionReceiptHeader, TransactionStatus};

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Serialize)]
pub struct TransactionReceipt {
    #[serde(flatten)]
    header: TransactionReceiptHeader,
    #[serde(skip)]
    trx_variant: u8, // always 1 for now
    trx: PackedTransaction,
}

impl TransactionReceipt {
    pub fn new(
        header: TransactionReceiptHeader,
        trx: PackedTransaction,
    ) -> Self {
        TransactionReceipt {
            header,
            trx_variant: 1,
            trx,
        }
    }

    pub fn trx(&self) -> &PackedTransaction {
        &self.trx
    }

    pub fn digest(&self) -> Result<Digest, WriteError> {
        Ok(Digest::hash(self.pack()?))
    }
}
