use std::collections::HashSet;

use pulsevm_crypto::Bytes;
use pulsevm_error::ChainError;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;
use serde::Serialize;
use sha2::Digest as Sha2Digest;

use crate::utils::Digest;
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
        let digest: Digest = Digest::from_data(&digest);

        for signature in self.signatures.iter() {
            let public_key = signature.recover_public_key(&digest)?;
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

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr};

    use pulsevm_time::TimePointSec;

    use crate::{
        crypto::PrivateKey,
        id::Id,
        transaction::{SignedTransaction, Transaction, TransactionHeader},
    };

    #[test]
    fn test_signing_digest() {
        let private_key =
            PrivateKey::from_str("PVT_K1_2pjSqJxTbRHq8h8aHHTux81Ypscb36Q2syB8UJbZcUmxbfZdnT")
                .unwrap();
        let public_key = private_key.get_public_key();
        let tx = SignedTransaction::new(
            Transaction::new(
                TransactionHeader::new(TimePointSec::new(100), 1, 2, 4.into(), 3, 5.into()),
                vec![],
                vec![],
            ),
            HashSet::new(),
            vec![],
        );
        let chain_id =
            Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6")
                .unwrap();
        let signing_digest = tx
            .transaction
            .signing_digest(&chain_id, &tx.context_free_data)
            .unwrap();
        let hex_digest = hex::encode(signing_digest);
        assert_eq!(
            hex_digest,
            "667bb523586b34e4bff2913b421ddd356e0c9db5bc83c93fd65092d18bcdeeac"
        );
        let signed_tx = tx.sign(&private_key, &chain_id).unwrap();
        assert_eq!(signed_tx.signatures.len(), 1);
        let recovered_keys = signed_tx.recovered_keys(&chain_id).unwrap();
        assert_eq!(recovered_keys.len(), 1);
        assert!(recovered_keys.contains(&public_key));
    }
}
