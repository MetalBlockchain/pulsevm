use pulsevm_crypto::Digest;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::{NumBytes, Read, ReadError, Write, WriteError};
use serde::Serialize;

use crate::chain::Id;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionStatus {
    Executed,
    SoftFail,
    HardFail,
}

impl Read for TransactionStatus {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let status = u8::read(bytes, pos)?;

        match status {
            0 => Ok(TransactionStatus::Executed),
            1 => Ok(TransactionStatus::SoftFail),
            2 => Ok(TransactionStatus::HardFail),
            _ => Err(ReadError::ParseError),
        }
    }
}

impl NumBytes for TransactionStatus {
    fn num_bytes(&self) -> usize {
        1 // 1 byte for the status
    }
}

impl Write for TransactionStatus {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        match self {
            TransactionStatus::Executed => 0_u8.write(bytes, pos),
            TransactionStatus::SoftFail => 1_u8.write(bytes, pos),
            TransactionStatus::HardFail => 2_u8.write(bytes, pos),
            _ => Err(WriteError::TryFromIntError),
        }
    }
}

impl Serialize for TransactionStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let status = match self {
            TransactionStatus::Executed => "executed",
            TransactionStatus::SoftFail => "soft_fail",
            TransactionStatus::HardFail => "hard_fail",
        };
        serializer.serialize_str(status)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes)]
pub struct TransactionReceiptHeader {
    status: TransactionStatus,
    cpu_usage_us: u32,
    net_usage_words: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes)]
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