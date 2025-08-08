use std::collections::HashSet;

use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::Serialize;

use crate::chain::{
    PrivateKey, PublicKey, Signature, error::ChainError, transaction::transaction::Transaction,
};

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Serialize)]
pub struct SignedTransaction {
    transaction: Transaction,
    signatures: HashSet<Signature>,
}

impl SignedTransaction {
    pub fn new(transaction: Transaction, signatures: HashSet<Signature>) -> Self {
        Self {
            transaction,
            signatures,
        }
    }

    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub fn signatures(&self) -> &HashSet<Signature> {
        &self.signatures
    }

    #[must_use]
    pub fn recovered_keys(&self) -> Result<HashSet<PublicKey>, ChainError> {
        let mut recovered_keys: HashSet<PublicKey> = HashSet::new();
        let digest = self.transaction.digest()?;

        for signature in self.signatures.iter() {
            let public_key = signature
                .recover_public_key(&digest)
                .map_err(|e| ChainError::SignatureRecoverError(format!("{}", e)))?;
            recovered_keys.insert(public_key);
        }

        Ok(recovered_keys)
    }

    #[allow(dead_code)]
    pub fn sign(mut self, private_key: &PrivateKey) -> Result<Self, ChainError> {
        let digest = self.transaction.digest()?;
        let signature = private_key.sign(&digest);
        self.signatures.insert(signature);
        Ok(self)
    }
}
