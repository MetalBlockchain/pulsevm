use std::{
    fmt,
    str::FromStr,
};

use pulsevm_crypto::{
    Digest,
    K1PrivateKey,
};
use pulsevm_error::ChainError;
use serde::Deserialize;

use crate::crypto::{
    PublicKey,
    Signature,
};

/// A secp256k1 (`K1`) private key. Pure Rust throughout — parsing, string
/// encoding, public-key derivation and signing run through [`K1PrivateKey`].
///
/// Only `K1` is supported; the `R1` (secp256r1) suite is not reached on any
/// replay or consensus path and is not ported.
#[derive(Clone)]
pub struct PrivateKey {
    inner: K1PrivateKey,
}

impl PrivateKey {
    pub fn sign(&self, digest: &Digest) -> Result<Signature, ChainError> {
        Ok(Signature::new(self.inner.sign(digest.as_bytes())))
    }

    pub fn new_k1_from_string(s: &str) -> Result<Self, ChainError> {
        let inner = K1PrivateKey::from_seed_string(s)
            .map_err(|e| ChainError::TransactionError(e.to_string()))?;
        Ok(PrivateKey { inner })
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey::new(self.inner.public_key())
    }

    /// Generates a random K1 private key.
    pub fn random() -> Self {
        PrivateKey {
            inner: K1PrivateKey::random(),
        }
    }
}

impl FromStr for PrivateKey {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = K1PrivateKey::from_string(s)
            .map_err(|e| ChainError::TransactionError(e.to_string()))?;
        Ok(PrivateKey { inner })
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public_key", &self.get_public_key())
            .finish()
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.to_string())
    }
}

impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PrivateKey::from_str(&s).map_err(serde::de::Error::custom)
    }
}
