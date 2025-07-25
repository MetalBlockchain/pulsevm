use core::fmt;
use std::str::FromStr;

use pulsevm_serialization::{NumBytes, Read, Write};
use secp256k1::hashes::sha256::{self, Hash};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Id(pub [u8; 32]);

impl Id {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn zero() -> Self {
        Id([0u8; 32])
    }

    pub fn from_sha256(hash: &sha256::Hash) -> Self {
        let mut id = [0u8; 32];
        id.copy_from_slice(hash.as_ref());
        Id(id)
    }
}

impl FromStr for Id {
    type Err = bs58::decode::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = bs58::decode(s).as_cb58(None).into_vec()?;
        if value.len() != 32 {
            return Err(bs58::decode::Error::BufferTooSmall);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&value);
        Ok(Id(id))
    }
}

impl NumBytes for Id {
    fn num_bytes(&self) -> usize {
        32
    }
}

impl Write for Id {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), pulsevm_serialization::WriteError> {
        if *pos + 32 > bytes.len() {
            return Err(pulsevm_serialization::WriteError::NotEnoughSpace);
        }
        bytes[*pos..*pos + 32].copy_from_slice(&self.0);
        *pos += 32;
        Ok(())
    }
}

impl Read for Id {
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        if *pos + 32 > data.len() {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&data[*pos..*pos + 32]);
        *pos += 32;
        Ok(Id(id))
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = bs58::encode(self.0).as_cb58(None).into_string();
        write!(f, "{}", value)
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
        Ok(Id(id))
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
        Ok(Id(id))
    }
}

impl Into<Vec<u8>> for Id {
    fn into(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<Hash> for Id {
    fn from(hash: Hash) -> Self {
        let mut id = [0u8; 32];
        id.copy_from_slice(hash.as_ref());
        Id(id)
    }
}

#[cfg(test)]
mod tests {
    use super::Id;
    use std::str::FromStr;

    #[test]
    fn test_id_from_str() {
        let id = Id::from_str("2iMormvesjkHEuF4toW2WGvvKsrrFkytLjTjRWCvis43pTC3AJ").unwrap();
        assert_eq!(
            hex::encode(id.as_bytes()),
            "e19b30bc0bfabfab01c9260469fab7529ae88987b2eb337dac5650305226b38e"
        );
    }
}
