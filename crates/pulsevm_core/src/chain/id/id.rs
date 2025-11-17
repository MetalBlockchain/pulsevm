use core::fmt;
use std::{error::Error, str::FromStr};

use pulsevm_crypto::FixedBytes;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct Id(pub FixedBytes<32>);

impl Id {
    pub fn new(bytes: [u8; 32]) -> Self {
        Id(FixedBytes(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0.0
    }

    pub fn zero() -> Self {
        Id(FixedBytes::default())
    }
}

#[derive(Debug)]
pub struct IdParseError;

impl fmt::Display for IdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid hex string for id")
    }
}

impl Error for IdParseError {}

impl FromStr for Id {
    type Err = IdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| IdParseError)?;

        if bytes.len() != 32 {
            return Err(IdParseError);
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Id(FixedBytes(array)))
    }
}

impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let hex_string = hex::encode(self.0);
        serializer.serialize_str(&hex_string)
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl TryFrom<&[u8]> for Id {
    type Error = pulsevm_serialization::ReadError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(value);
        Ok(Id(FixedBytes(id)))
    }
}

impl TryFrom<Vec<u8>> for Id {
    type Error = pulsevm_serialization::ReadError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&value);
        Ok(Id(FixedBytes(id)))
    }
}

impl Into<Vec<u8>> for Id {
    fn into(self) -> Vec<u8> {
        self.0.0.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::Id;
    use std::str::FromStr;

    #[test]
    fn test_id_from_str() {
        let id = Id::from_str("e19b30bc0bfabfab01c9260469fab7529ae88987b2eb337dac5650305226b38e")
            .unwrap();
        assert_eq!(
            hex::encode(id.as_bytes()),
            "e19b30bc0bfabfab01c9260469fab7529ae88987b2eb337dac5650305226b38e"
        );
    }
}
