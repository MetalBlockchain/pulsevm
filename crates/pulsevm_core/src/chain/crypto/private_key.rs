use std::{fmt, str::FromStr};

use cxx::SharedPtr;
use pulsevm_error::ChainError;
use pulsevm_ffi::{CxxPrivateKey, sign_digest_with_private_key};

use crate::{
    crypto::{PublicKey, Signature},
    utils::Digest,
};

#[derive(Clone)]
pub struct PrivateKey {
    inner: SharedPtr<CxxPrivateKey>,
}

impl PrivateKey {
    pub fn sign(&self, digest: &Digest) -> Result<Signature, ChainError> {
        let cxx_sig = sign_digest_with_private_key(&digest, &self.inner).map_err(|e| ChainError::TransactionError(e.to_string()))?;
        Ok(Signature::new(cxx_sig))
    }

    pub fn new_k1_from_string(s: &str) -> Result<Self, ChainError> {
        let hash = pulsevm_ffi::make_shared_digest_from_string(s);
        let cxx_key = pulsevm_ffi::make_k1_private_key(&hash);
        Ok(PrivateKey { inner: cxx_key })
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey::new(self.inner.get_public_key())
    }
}

impl FromStr for PrivateKey {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cxx_key = pulsevm_ffi::parse_private_key(s).map_err(|e| ChainError::TransactionError(e.to_string()))?;
        Ok(PrivateKey { inner: cxx_key })
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.to_string())
    }
}
