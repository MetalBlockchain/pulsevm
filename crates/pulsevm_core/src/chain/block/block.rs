use std::collections::VecDeque;

use pulsevm_crypto::{Digest, FixedBytes};
use pulsevm_error::ChainError;
use pulsevm_ffi::Database;
use pulsevm_name_macro::name;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;
use serde::{Serialize, ser::SerializeStruct};

use crate::{
    chain::{Name, block::BlockTimestamp, id::Id, transaction::TransactionReceipt},
    crypto::Signature,
    state_history::StateHistoryLog,
    utils::pulse_assert,
};

#[derive(Debug, Default, Clone, Read, Write, NumBytes)]
pub struct BlockHeader {
    pub timestamp: BlockTimestamp,
    pub producer: Name,
    pub confirmed: u16,
    pub previous: Id,
    pub transaction_mroot: Digest,
    pub action_mroot: Id,
    pub schedule_version: u32,
    pub new_producers: Option<Vec<u8>>, // Placeholder for new producers, we don't use this for now
    pub header_extensions: Vec<(u16, Vec<u8>)>, // Placeholder for header extensions, we don't use this for now
}

impl BlockHeader {
    fn digest(&self) -> Result<Digest, ChainError> {
        let packed = self
            .pack()
            .map_err(|e| ChainError::SerializationError(e.to_string()))?;
        Ok(Digest::hash(&packed))
    }

    fn block_num(&self) -> u32 {
        Self::num_from_id(&self.previous) + 1
    }

    #[inline]
    pub fn num_from_id(id: &Id) -> u32 {
        // First 4 bytes contain the block number in big-endian.
        u32::from_be_bytes(id.0.0[0..4].try_into().unwrap())
    }

    #[inline]
    pub fn id_from_num(id: &Id) -> u32 {
        // First 4 bytes contain the block number in big-endian.
        u32::from_be_bytes(id.0.0[0..4].try_into().unwrap())
    }

    #[inline]
    pub fn calculate_id(&self) -> Result<Id, ChainError> {
        let mut result = self.digest()?; // exclude producer_signature etc.
        let bn_be = self.block_num().to_be_bytes(); // endian_reverse_u32 on LE == write BE bytes
        // Overwrite the first 4 bytes with the big-endian block number
        result.0[0..4].copy_from_slice(&bn_be);
        Ok(Id(FixedBytes(result.0)))
    }

    pub fn validate(&self, db: &Database) -> Result<(), ChainError> {
        // TODO: Allow some small time skew (e.g. 1 second) to account for clock differences between nodes
        pulse_assert(
            self.timestamp <= BlockTimestamp::now(),
            ChainError::BlockError("block timestamp is in the future".into()),
        )?;
        pulse_assert(
            db.is_account(self.producer.as_u64())?,
            ChainError::BlockError("producer account does not exist".into()),
        )?;
        pulse_assert(
            self.confirmed == 0,
            ChainError::BlockError("confirmed count must be 0".into()),
        )?;
        // TODO: Validate previous block ID if we have the previous block available
        // TODO: Validate transaction_mroot and action_mroot if we have the transactions available
        pulse_assert(
            self.schedule_version == 0,
            ChainError::BlockError("schedule version must be 0".into()),
        )?;
        pulse_assert(
            self.new_producers.is_none(),
            ChainError::BlockError("new producers should be none".into()),
        )?;
        pulse_assert(
            self.header_extensions.is_empty(),
            ChainError::BlockError("header extensions not supported".into()),
        )?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Read, Write, NumBytes)]
pub struct SignedBlockHeader {
    pub header: BlockHeader,
    pub signature: Signature,
}

impl SignedBlockHeader {
    pub fn validate(&self, db: &Database) -> Result<(), ChainError> {
        self.header.validate(db)?;
        // TODO: validate signature if we have the producer's public key available
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Read, Write, NumBytes)]
pub struct SignedBlock {
    pub signed_block_header: SignedBlockHeader,
    pub transactions: VecDeque<TransactionReceipt>, // Placeholder for transactions, we don't use this for now
    pub block_extensions: Vec<(u16, Vec<u8>)>, // Placeholder for header extensions, we don't use this for now
}

impl SignedBlock {
    pub fn new(
        parent_id: Id,
        timestamp: BlockTimestamp,
        transaction_receipts: VecDeque<TransactionReceipt>,
        transaction_mroot: Digest,
    ) -> Self {
        SignedBlock {
            signed_block_header: SignedBlockHeader {
                header: BlockHeader {
                    timestamp,
                    producer: Name::from(name!("pulse")), // Placeholder producer name
                    confirmed: 0,                         // Placeholder confirmed count
                    previous: parent_id,
                    transaction_mroot: transaction_mroot,
                    action_mroot: Id::default(), // Placeholder action merkle root
                    schedule_version: 0,         // Placeholder schedule version
                    new_producers: None,         // Placeholder for new producers
                    header_extensions: vec![],   // Placeholder for header extensions
                },
                signature: Signature::default(), // Placeholder signature
            },
            transactions: transaction_receipts,
            block_extensions: vec![],
        }
    }

    pub fn id(&self) -> Result<Id, ChainError> {
        self.signed_block_header.header.calculate_id()
    }

    pub fn previous_id(&self) -> &Id {
        &self.signed_block_header.header.previous
    }

    pub fn block_num(&self) -> u32 {
        self.signed_block_header.header.block_num()
    }

    pub fn timestamp(&self) -> &BlockTimestamp {
        &self.signed_block_header.header.timestamp
    }

    pub fn validate(&self, db: &Database) -> Result<(), ChainError> {
        self.signed_block_header.validate(db)?;

        pulse_assert(
            self.transactions.len() > 0,
            ChainError::BlockError("block has no transactions".into()),
        )?;
        pulse_assert(
            self.block_extensions.is_empty(),
            ChainError::BlockError("block extensions not supported".into()),
        )?;

        Ok(())
    }
}

impl Serialize for SignedBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Block", 8)?;
        state.serialize_field("timestamp", &self.signed_block_header.header.timestamp)?;
        state.serialize_field("producer", &self.signed_block_header.header.producer)?;
        state.serialize_field("confirmed", &self.signed_block_header.header.confirmed)?;
        state.serialize_field("previous", &self.signed_block_header.header.previous)?;
        state.serialize_field(
            "transaction_mroot",
            &self.signed_block_header.header.transaction_mroot,
        )?;
        state.serialize_field("transactions", &self.transactions)?;
        state.serialize_field(
            "id",
            &self.signed_block_header.header.calculate_id().unwrap(),
        )?;
        state.serialize_field("block_num", &self.signed_block_header.header.block_num())?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use pulsevm_serialization::{Read, Write};

    use crate::block::SignedBlock;

    #[test]
    pub fn test_block_serialization() {
        let signed_block = SignedBlock::default();
        let packed = signed_block.pack().unwrap();
        let unpacked = SignedBlock::read(&packed, &mut 0).unwrap();
    }
}
