use std::{
    fmt::{
        self,
        Debug,
        Display,
    },
    hash::{
        Hash,
        Hasher,
    },
    str::FromStr,
};

use pulsevm_crypto::{
    Digest,
    FixedBytes,
    K1Signature,
};
use pulsevm_error::ChainError;
use pulsevm_serialization::{
    NumBytes,
    Read,
    ReadError,
    Write,
    WriteError,
};
use serde::{
    Deserialize,
    Serialize,
};

use crate::crypto::PublicKey;

/// A recoverable secp256k1 (`K1`) signature. Pure Rust: parse, pack, recover and
/// string encoding all run through [`K1Signature`].
#[derive(Clone, Copy)]
pub struct Signature {
    inner: K1Signature,
}

impl Signature {
    pub fn new(inner: K1Signature) -> Self {
        Signature { inner }
    }

    pub fn recover_public_key(&self, digest: &Digest) -> Result<PublicKey, ChainError> {
        let key = self
            .inner
            .recover(digest.as_bytes())
            .map_err(|e| ChainError::TransactionError(e.to_string()))?;
        Ok(PublicKey::new(key))
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.to_string())
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.to_string())
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.to_packed().cmp(&other.inner.to_packed())
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.inner.compact65() == other.inner.compact65()
    }
}

impl Eq for Signature {}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.to_packed().hash(state);
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.inner.to_string())
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
                let sig = K1Signature::from_string(v)
                    .map_err(|e| E::custom(format!("failed to parse signature: {}", e)))?;
                Ok(Signature { inner: sig })
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
        let sig = K1Signature::from_packed(packed.as_ref())
            .map_err(|e| ReadError::CustomError(e.to_string()))?;
        Ok(Signature { inner: sig })
    }
}

impl Write for Signature {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let packed = FixedBytes::<66>(self.inner.to_packed());
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
        let sig = K1Signature::from_string(s).map_err(|e| {
            ChainError::TransactionError(format!("failed to parse signature: {}", e))
        })?;
        Ok(Signature { inner: sig })
    }
}
