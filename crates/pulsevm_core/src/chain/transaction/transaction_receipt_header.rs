use std::fmt;

use pulsevm_proc_macros::{
    NumBytes,
    Read,
    Write,
};
use pulsevm_serialization::{
    NumBytes,
    Read,
    ReadError,
    VarUint32,
    Write,
    WriteError,
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionStatus {
    Executed,
    SoftFail,
    HardFail,
    Delayed,
    Expired,
}

impl fmt::Display for TransactionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status_str = match self {
            TransactionStatus::Executed => "Executed",
            TransactionStatus::SoftFail => "SoftFail",
            TransactionStatus::HardFail => "HardFail",
            TransactionStatus::Delayed => "Delayed",
            TransactionStatus::Expired => "Expired",
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
            3 => Ok(TransactionStatus::Delayed),
            4 => Ok(TransactionStatus::Expired),
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
            TransactionStatus::Delayed => 3_u8.write(bytes, pos),
            TransactionStatus::Expired => 4_u8.write(bytes, pos),
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
            TransactionStatus::Delayed => "delayed",
            TransactionStatus::Expired => "expired",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_status_round_trips_and_has_canonical_text() {
        let cases = [
            (TransactionStatus::Executed, "Executed", "\"executed\""),
            (TransactionStatus::SoftFail, "SoftFail", "\"soft_fail\""),
            (TransactionStatus::HardFail, "HardFail", "\"hard_fail\""),
            (TransactionStatus::Delayed, "Delayed", "\"delayed\""),
            (TransactionStatus::Expired, "Expired", "\"expired\""),
        ];
        for (status, display, json) in cases {
            let packed = status.pack().unwrap();
            assert_eq!(TransactionStatus::read(&packed, &mut 0).unwrap(), status);
            assert_eq!(status.num_bytes(), 1);
            assert_eq!(status.to_string(), display);
            assert_eq!(serde_json::to_string(&status).unwrap(), json);
        }
        assert_eq!(TransactionStatus::default(), TransactionStatus::HardFail);
        assert!(TransactionStatus::read(&[5], &mut 0).is_err());
    }

    #[test]
    fn receipt_header_constructor_preserves_billing_fields() {
        let header =
            TransactionReceiptHeader::new(TransactionStatus::Executed, 123, VarUint32(456));
        assert_eq!(header.status, TransactionStatus::Executed);
        assert_eq!(header.cpu_usage_us, 123);
        assert_eq!(header.net_usage_words, VarUint32(456));
        let packed = header.pack().unwrap();
        assert_eq!(
            TransactionReceiptHeader::read(&packed, &mut 0).unwrap(),
            header
        );
    }
}
