use std::{
    fmt::{self, Debug, Display},
    hash::{Hash, Hasher},
    str::FromStr,
};

use cxx::SharedPtr;
use pulsevm_crypto::FixedBytes;
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
        let cxx_pk = recover_public_key_from_signature(&self.inner, &digest)
            .map_err(|e| ChainError::TransactionError(e.to_string()))?;
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
                let cxx_sig = pulsevm_ffi::parse_signature(v)
                    .map_err(|e| E::custom(format!("failed to parse signature: {}", e)))?;
                Ok(Signature { inner: cxx_sig })
            }
        }

        deserializer.deserialize_str(SigVisitor)
    }
}

impl NumBytes for Signature {
    fn num_bytes(&self) -> usize {
        66 // Fixed size for packed signature representation
    }
}

impl Read for Signature {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let packed = FixedBytes::<66>::read(bytes, pos)?;
        let cxx_key = pulsevm_ffi::parse_signature_from_bytes(packed.as_ref())
            .map_err(|e| ReadError::CustomError(e.to_string()))?;
        Ok(Signature { inner: cxx_key })
    }
}

impl Write for Signature {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let packed: FixedBytes<66> = self.inner.packed_bytes().try_into().map_err(|_| {
            WriteError::CustomError("Failed to convert packed signature to FixedBytes<66>".into())
        })?;
        packed.write(bytes, pos)
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::from_str(
            "SIG_K1_111111111111111111111111111111111111111111111111111111111111111116uk5ne",
        )
        .unwrap()
    }
}

impl FromStr for Signature {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cxx_sig = pulsevm_ffi::parse_signature(s).map_err(|e| {
            ChainError::TransactionError(format!("failed to parse signature: {}", e))
        })?;
        Ok(Signature { inner: cxx_sig })
    }
}
