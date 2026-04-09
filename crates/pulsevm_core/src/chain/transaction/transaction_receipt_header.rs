use std::fmt;

use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::{NumBytes, Read, ReadError, VarUint32, Write, WriteError};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionStatus {
    Executed,
    SoftFail,
    HardFail,
}

impl fmt::Display for TransactionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status_str = match self {
            TransactionStatus::Executed => "Executed",
            TransactionStatus::SoftFail => "SoftFail",
            TransactionStatus::HardFail => "HardFail",
        };
        write!(f, "{}", status_str)
    }
}

impl Default for TransactionStatus {
    fn default() -> Self {
        TransactionStatus::HardFail
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Read, Default, Write, NumBytes, Serialize)]
pub struct TransactionReceiptHeader {
    pub status: TransactionStatus,
    pub cpu_usage_us: u32,
    pub net_usage_words: VarUint32,
}

impl TransactionReceiptHeader {
    pub fn new(status: TransactionStatus, cpu_usage_us: u32, net_usage_words: VarUint32) -> Self {
        TransactionReceiptHeader {
            status,
            cpu_usage_us,
            net_usage_words,
        }
    }
}
