use cxx::SharedPtr;
use pulsevm_error::ChainError;
use pulsevm_ffi::{CxxPrivateKey, sign_digest_with_private_key};

use crate::{crypto::Signature, utils::Digest};

pub struct PrivateKey {
    inner: SharedPtr<CxxPrivateKey>,
}

impl PrivateKey {
    pub fn sign(&self, digest: &Digest) -> Result<Signature, ChainError> {
        let cxx_sig = sign_digest_with_private_key(&digest, &self.inner)
            .map_err(|e| ChainError::TransactionError(e.to_string()))?;
        Ok(Signature::new(cxx_sig))
    }
}