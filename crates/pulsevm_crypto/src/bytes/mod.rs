use core::fmt;

use pulsevm_serialization::{NumBytes, Read, ReadError, Write};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    #[inline]
    pub fn new(data: Vec<u8>) -> Self {
        Bytes(data)
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Bytes {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::encode(self.0.as_slice()).fmt(f)
    }
}

impl Serialize for Bytes {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let hex_string = hex::encode(&self.0);
        serializer.serialize_str(&hex_string)
    }
}

impl<'de> Deserialize<'de> for Bytes {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_string = String::deserialize(deserializer)?;
        let bytes = hex::decode(hex_string).map_err(serde::de::Error::custom)?;
        Ok(Bytes(bytes))
    }
}

impl From<Vec<u8>> for Bytes {
    #[inline]
    fn from(data: Vec<u8>) -> Self {
        Bytes(data)
    }
}

impl From<&[u8]> for Bytes {
    #[inline]
    fn from(data: &[u8]) -> Self {
        Bytes(data.to_vec())
    }
}

impl NumBytes for Bytes {
    #[inline]
    fn num_bytes(&self) -> usize {
        4 + self.0.len() // 4 bytes for length + data
    }
}

impl Read for Bytes {
    #[inline]
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let len = usize::read(bytes, pos)?;

        // bounds check
        if bytes.len() < *pos + len {
            return Err(ReadError::NotEnoughBytes);
        }

        let start = *pos;
        let end = start + len;
        *pos = end;

        Ok(Bytes(bytes[start..end].to_vec()))
    }
}

impl Write for Bytes {
    #[inline]
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), pulsevm_serialization::WriteError> {
        let len = self.0.len();
        usize::write(&len, bytes, pos)?;
        if bytes.len() < *pos + len {
            return Err(pulsevm_serialization::WriteError::NotEnoughSpace);
        }
        bytes[*pos..*pos + len].copy_from_slice(&self.0);
        *pos += len;
        Ok(())
    }
}

impl AsRef<[u8]> for Bytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_display() {
        let bytes = Bytes::new(vec![0x12, 0x34, 0x56, 0x78]);
        assert_eq!(bytes.to_string(), "12345678");
    }
}
