use std::{
    fmt::{self, Debug, Display},
    hash::{Hash, Hasher},
};

use cxx::SharedPtr;
use pulsevm_ffi::CxxPublicKey;
use pulsevm_serialization::{NumBytes, Read, ReadError, Write, WriteError};
use serde::Serialize;

#[derive(Clone)]
pub struct PublicKey {
    inner: SharedPtr<CxxPublicKey>,
}

impl PublicKey {
    pub fn new(inner: SharedPtr<CxxPublicKey>) -> Self {
        PublicKey { inner }
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.to_string_rust())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.to_string_rust())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.cmp(&other.inner) == 0
    }
}

impl Eq for PublicKey {}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.pack().hash(state);
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.inner.to_string_rust())
    }
}

impl NumBytes for PublicKey {
    fn num_bytes(&self) -> usize {
        self.inner.num_bytes()
    }
}

impl Read for PublicKey {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let cxx_key = pulsevm_ffi::parse_public_key_from_bytes(bytes, pos)
            .map_err(|e| ReadError::CustomError(e.to_string()))?;
        Ok(PublicKey { inner: cxx_key })
    }
}

impl Write for PublicKey {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let packed = self.inner.pack();
        let end_pos = *pos + packed.len();
        if end_pos > bytes.len() {
            return Err(WriteError::NotEnoughSpace);
        }
        bytes[*pos..end_pos].copy_from_slice(&packed);
        *pos = end_pos;
        Ok(())
    }
}
