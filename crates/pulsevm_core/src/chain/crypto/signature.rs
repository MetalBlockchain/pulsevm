use std::{
    fmt::{self, Debug, Display},
    hash::{Hash, Hasher},
};

use cxx::SharedPtr;
use pulsevm_error::ChainError;
use pulsevm_ffi::{CxxSignature, recover_public_key_from_signature};
use pulsevm_serialization::{NumBytes, Read, ReadError, Write, WriteError};
use serde::{Deserialize, Serialize};

use crate::{crypto::PublicKey, utils::Digest};

#[derive(Clone)]
pub struct Signature {
    inner: SharedPtr<CxxSignature>,
}

impl Signature {
    pub fn new(inner: SharedPtr<CxxSignature>) -> Self {
        Signature { inner }
    }

    pub fn recover_public_key(&self, digest: &Digest) -> Result<PublicKey, ChainError> {
        let cxx_pk = recover_public_key_from_signature(&self.inner, &digest).map_err(|e| ChainError::TransactionError(e.to_string()))?;
        Ok(PublicKey::new(cxx_pk))
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.to_string_rust())
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.to_string_rust())
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.inner.cmp(&other.inner) == 0
    }
}

impl Eq for Signature {}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.packed_bytes().hash(state);
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.inner.to_string_rust())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SigVisitor;

        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string representing a signature")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let cxx_sig = pulsevm_ffi::parse_signature(v).map_err(|e| E::custom(format!("failed to parse signature: {}", e)))?;
                Ok(Signature { inner: cxx_sig })
            }
        }

        deserializer.deserialize_str(SigVisitor)
    }
}

impl NumBytes for Signature {
    fn num_bytes(&self) -> usize {
        self.inner.num_bytes().num_bytes() + self.inner.num_bytes()
    }
}

impl Read for Signature {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let packed = Vec::<u8>::read(bytes, pos)?;
        let cxx_key = pulsevm_ffi::parse_signature_from_bytes(&packed, pos).map_err(|e| ReadError::CustomError(e.to_string()))?;
        Ok(Signature { inner: cxx_key })
    }
}

impl Write for Signature {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let packed = self.inner.packed_bytes();
        let end_pos = *pos + packed.len();
        if end_pos > bytes.len() {
            return Err(WriteError::NotEnoughSpace);
        }
        bytes[*pos..end_pos].copy_from_slice(&packed);
        *pos = end_pos;
        Ok(())
    }
}

impl Default for Signature {
    fn default() -> Self {
        let empty_sig = SharedPtr::null();
        Signature { inner: empty_sig }
    }
}
