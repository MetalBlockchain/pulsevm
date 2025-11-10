use std::collections::HashSet;

use pulsevm_crypto::Bytes;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;
use secp256k1::hashes::{Hash, HashEngine, sha256};
use serde::Serialize;

use crate::chain::{
    error::ChainError,
    id::Id,
    secp256k1::{PrivateKey, PublicKey, Signature},
    transaction::transaction::Transaction,
};

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Serialize)]
pub struct SignedTransaction {
    transaction: Transaction,
    signatures: HashSet<Signature>,
    context_free_data: Vec<Bytes>,
}

impl SignedTransaction {
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

    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub fn signatures(&self) -> &HashSet<Signature> {
        &self.signatures
    }

    #[must_use]
    pub fn recovered_keys(&self, chain_id: &Id) -> Result<HashSet<PublicKey>, ChainError> {
        let mut recovered_keys: HashSet<PublicKey> = HashSet::new();
        let digest = self
            .transaction
            .signing_digest(chain_id, &self.context_free_data)?;

        for signature in self.signatures.iter() {
            let public_key = signature
                .recover_public_key(&digest)
                .map_err(|e| ChainError::SignatureRecoverError(format!("{}", e)))?;
            recovered_keys.insert(public_key);
        }

        Ok(recovered_keys)
    }

    #[allow(dead_code)]
    pub fn sign(mut self, private_key: &PrivateKey, chain_id: &Id) -> Result<Self, ChainError> {
        let digest = self
            .transaction
            .signing_digest(chain_id, &self.context_free_data)?;
        let signature = private_key.sign(&digest);
        self.signatures.insert(signature);
        Ok(self)
    }
}

pub fn signing_digest(
    chain_id: &Id,
    trx_bytes: &Vec<u8>,
    cfd_bytes: &Vec<Bytes>,
) -> Result<sha256::Hash, ChainError> {
    let cf_hash = if cfd_bytes.is_empty() {
        [0u8; 32]
    } else {
        let cfd_bytes = cfd_bytes.pack().map_err(|e| {
            ChainError::SerializationError(format!("failed to pack transaction: {}", e))
        })?;
        sha256::Hash::hash(&cfd_bytes).to_byte_array()
    };

    let mut eng = sha256::Hash::engine();
    eng.input(&chain_id.0);
    eng.input(&trx_bytes);
    eng.input(&cf_hash);

    Ok(sha256::Hash::from_engine(eng))
}
