use std::collections::HashSet;

use pulsevm_crypto::Bytes;
use pulsevm_error::ChainError;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;
use serde::{Serialize, ser::SerializeStruct};
use sha2::Digest;

use crate::{
    block::BlockTimestamp,
    chain::{
        id::Id,
        transaction::{SignedTransaction, TransactionHeader, signed_transaction::signing_digest},
    },
    crypto::PrivateKey,
    utils::pulse_assert,
};

use super::action::Action;

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Hash, Default)]
pub struct Transaction {
    pub header: TransactionHeader,
    pub context_free_actions: Vec<Action>, // Context-free actions, if any
    pub actions: Vec<Action>,              // Actions to be executed in this transaction
    pub transaction_extensions: Vec<(u16, Vec<u8>)>, // We don't use this for now
}

impl Transaction {
    pub fn new(
        header: TransactionHeader,
        context_free_actions: Vec<Action>,
        actions: Vec<Action>,
    ) -> Self {
        Self {
            header,
            context_free_actions,
            actions,
            transaction_extensions: vec![],
        }
    }

    pub fn id(&self) -> Result<Id, ChainError> {
        Ok(Id::new(self.digest()?))
    }

    fn digest(&self) -> Result<[u8; 32], ChainError> {
        let bytes: Vec<u8> = self.pack().map_err(|e| {
            ChainError::SerializationError(format!("failed to pack transaction: {}", e))
        })?;
        Ok(sha2::Sha256::digest(&bytes).into())
    }

    // Helper function for testing
    pub fn sign(
        &self,
        private_key: &PrivateKey,
        chain_id: &Id,
    ) -> Result<SignedTransaction, ChainError> {
        let signed_transaction = SignedTransaction::new(self.clone(), HashSet::new(), vec![]);

        signed_transaction.sign(private_key, chain_id)
    }

    pub fn signing_digest(
        &self,
        chain_id: &Id,
        cfd_bytes: &Vec<Bytes>,
    ) -> Result<[u8; 32], ChainError> {
        let trx_bytes: Vec<u8> = self.pack().map_err(|e| {
            ChainError::SerializationError(format!("failed to pack transaction: {}", e))
        })?;

        signing_digest(chain_id, &trx_bytes, cfd_bytes)
    }

    pub fn validate(&self, block_timestamp: &BlockTimestamp) -> Result<(), ChainError> {
        pulse_assert(
            self.header.delay_sec().0 == 0,
            ChainError::TransactionError("delay larger than 0 not supported".into()),
        )?;
        pulse_assert(
            self.header.expiration().sec_since_epoch()
                >= block_timestamp.to_time_point().sec_since_epoch(),
            ChainError::TransactionError(format!(
                "transaction expired at {}",
                self.header.expiration.to_eos_string()
            )),
        )?;
        pulse_assert(
            self.transaction_extensions.len() == 0,
            ChainError::TransactionError(format!(
                "transaction extensions are not supported right now"
            )),
        )?;
        return Ok(());
    }
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Transaction", 4)?;
        state.serialize_field("expiration", &self.header.expiration)?;
        state.serialize_field("max_net_usage_words", &self.header.max_net_usage_words)?;
        state.serialize_field("max_cpu_usage_ms", &self.header.max_cpu_usage)?;
        state.serialize_field("actions", &self.actions)?;
        state.end()
    }
}
