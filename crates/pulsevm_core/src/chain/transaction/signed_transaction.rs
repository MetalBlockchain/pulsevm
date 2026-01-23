use std::collections::HashSet;

use pulsevm_crypto::Bytes;
use pulsevm_error::ChainError;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;
use serde::Serialize;
use sha2::Digest;

use crate::{
    chain::{id::Id, transaction::transaction::Transaction},
    crypto::{PrivateKey, PublicKey, Signature},
};

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Serialize, Default)]
pub struct SignedTransaction {
    transaction: Transaction,
    signatures: HashSet<Signature>,
    context_free_data: Vec<Bytes>,
}

impl SignedTransaction {
    #[inline]
    pub fn new(
        transaction: Transaction,
        signatures: HashSet<Signature>,
        context_free_data: Vec<Bytes>,
    ) -> Self {
        Self {
            transaction,
            signatures,
            context_free_data,
        }
    }

    #[inline]
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    #[inline]
    pub fn signatures(&self) -> &HashSet<Signature> {
        &self.signatures
    }

    #[must_use]
    #[inline]
    pub fn recovered_keys(&self, chain_id: &Id) -> Result<HashSet<PublicKey>, ChainError> {
        let mut recovered_keys: HashSet<PublicKey> = HashSet::new();
        let digest = self
            .transaction
            .signing_digest(chain_id, &self.context_free_data)?;

        for signature in self.signatures.iter() {
            let public_key = signature
                .recover_public_key(&digest.into())
                .map_err(|e| ChainError::SignatureRecoverError(format!("{}", e)))?;
            recovered_keys.insert(public_key);
        }

        Ok(recovered_keys)
    }

    #[inline]
    pub fn sign(mut self, private_key: &PrivateKey, chain_id: &Id) -> Result<Self, ChainError> {
        let digest = self
            .transaction
            .signing_digest(chain_id, &self.context_free_data)?;
        let signature = private_key.sign(&digest.into())?;
        self.signatures.insert(signature);
        Ok(self)
    }
}

#[inline]
pub fn signing_digest(
    chain_id: &Id,
    trx_bytes: &Vec<u8>,
    cfd_bytes: &Vec<Bytes>,
) -> Result<[u8; 32], ChainError> {
    let cf_hash = if cfd_bytes.is_empty() {
        [0u8; 32]
    } else {
        let cfd_bytes = cfd_bytes.pack().map_err(|e| {
            ChainError::SerializationError(format!("failed to pack transaction: {}", e))
        })?;
        sha2::Sha256::digest(&cfd_bytes).into()
    };

    // main signing hash
    let mut hasher = sha2::Sha256::new();
    hasher.update(&chain_id.0);
    hasher.update(trx_bytes);
    hasher.update(&cf_hash);

    Ok(hasher.finalize().into())
}
