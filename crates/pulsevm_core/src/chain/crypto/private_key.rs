use std::str::FromStr;

use cxx::SharedPtr;
use pulsevm_error::ChainError;
use pulsevm_ffi::{CxxPrivateKey, sign_digest_with_private_key};

use crate::{
    crypto::{PublicKey, Signature},
    utils::Digest,
};

pub struct PrivateKey {
    inner: SharedPtr<CxxPrivateKey>,
}

impl PrivateKey {
    pub fn sign(&self, digest: &Digest) -> Result<Signature, ChainError> {
        let cxx_sig = sign_digest_with_private_key(&digest, &self.inner).map_err(|e| ChainError::TransactionError(e.to_string()))?;
        Ok(Signature::new(cxx_sig))
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
