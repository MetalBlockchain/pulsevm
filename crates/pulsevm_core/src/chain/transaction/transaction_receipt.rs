use pulsevm_crypto::Digest;
use pulsevm_serialization::{
    NumBytes,
    Read,
    ReadError,
    Write,
    WriteError,
};
use serde::Serialize;

use crate::chain::{
    id::Id,
    transaction::{
        PackedTransaction,
        TransactionReceiptHeader,
        TransactionStatus,
    },
};

/// Antelope receipt payload. A normal input transaction commits its packed
/// form; generated transactions commit only their id, because every validator
/// obtains their bytes from the durable generated-transaction record.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReceiptTransaction {
    Id(Id),
    Packed(PackedTransaction),
}

impl Read for ReceiptTransaction {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        match u8::read(bytes, pos)? {
            0 => Ok(Self::Id(Id::read(bytes, pos)?)),
            1 => Ok(Self::Packed(PackedTransaction::read(bytes, pos)?)),
            _ => Err(ReadError::ParseError),
        }
    }
}

impl Write for ReceiptTransaction {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        match self {
            Self::Id(id) => {
                0u8.write(bytes, pos)?;
                id.write(bytes, pos)
            }
            Self::Packed(trx) => {
                1u8.write(bytes, pos)?;
                trx.write(bytes, pos)
            }
        }
    }
}

impl NumBytes for ReceiptTransaction {
    fn num_bytes(&self) -> usize {
        1 + match self {
            Self::Id(id) => id.num_bytes(),
            Self::Packed(trx) => trx.num_bytes(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransactionReceipt {
    #[serde(flatten)]
    header: TransactionReceiptHeader,
    #[serde(skip)]
    trx: ReceiptTransaction,
}

impl Read for TransactionReceipt {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        Ok(Self {
            header: TransactionReceiptHeader::read(bytes, pos)?,
            trx: ReceiptTransaction::read(bytes, pos)?,
        })
    }
}

impl Write for TransactionReceipt {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.header.write(bytes, pos)?;
        self.trx.write(bytes, pos)
    }
}

impl NumBytes for TransactionReceipt {
    fn num_bytes(&self) -> usize {
        self.header.num_bytes() + self.trx.num_bytes()
    }
}

impl TransactionReceipt {
    pub fn new(header: TransactionReceiptHeader, trx: PackedTransaction) -> Self {
        Self {
            header,
            trx: ReceiptTransaction::Packed(trx),
        }
    }

    pub fn for_id(header: TransactionReceiptHeader, transaction_id: Id) -> Self {
        Self {
            header,
            trx: ReceiptTransaction::Id(transaction_id),
        }
    }

    /// Packed input transaction when this is an input receipt. Scheduled
    /// receipts deliberately return `None`: their bytes live in Arena.
    pub fn packed_trx(&self) -> Option<&PackedTransaction> {
        match &self.trx {
            ReceiptTransaction::Packed(trx) => Some(trx),
            ReceiptTransaction::Id(_) => None,
        }
    }

    pub fn transaction_id(&self) -> &Id {
        match &self.trx {
            ReceiptTransaction::Id(id) => id,
            ReceiptTransaction::Packed(trx) => trx.id(),
        }
    }

    /// Consensus status committed by this receipt. Deferred transactions use
    /// `SoftFail` when their sender's `eosio::onerror` callback succeeds.
    pub fn status(&self) -> &TransactionStatus {
        &self.header.status
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
        let mut bytes = self.header.pack()?;
        match &self.trx {
            ReceiptTransaction::Id(id) => bytes.extend(id.pack()?),
            ReceiptTransaction::Packed(trx) => bytes.extend(trx.packed_digest()?.pack()?),
        }
        Ok(Digest::hash(bytes))
    }
}
