use pulsevm_serialization::{NumBytes, Read, ReadError, Write, WriteError};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransactionCompression {
    None,
    Zlib,
}

impl Write for TransactionCompression {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        match self {
            TransactionCompression::None => u8::write(&0, bytes, pos),
            TransactionCompression::Zlib => u8::write(&1, bytes, pos),
        }
    }
}

impl NumBytes for TransactionCompression {
    fn num_bytes(&self) -> usize {
        1
    }
}

impl Read for TransactionCompression {
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let value = u8::read(data, pos)?;
        match value {
            0 => Ok(TransactionCompression::None),
            1 => Ok(TransactionCompression::Zlib),
            _ => Err(ReadError::ParseError),
        }
    }
}

impl Serialize for TransactionCompression {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let status = match self {
            TransactionCompression::None => "none",
            TransactionCompression::Zlib => "zlib",
        };
        serializer.serialize_str(status)
    }
}

impl<'de> Deserialize<'de> for TransactionCompression {
    fn deserialize<D>(deserializer: D) -> Result<TransactionCompression, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "none" => Ok(TransactionCompression::None),
            "zlib" => Ok(TransactionCompression::Zlib),
            _ => Err(serde::de::Error::custom("unknown compression type")),
        }
    }
}
