use std::collections::VecDeque;

use pulsevm_chainbase::{ChainbaseObject, SecondaryIndex, SecondaryKey};
use pulsevm_crypto::Digest;
use pulsevm_proc_macros::{NumBytes, Read, Write, name};
use pulsevm_serialization::Write;
use secp256k1::hashes::{Hash, sha256};
use serde::{Serialize, ser::SerializeStruct};

use crate::chain::{
    Name, block::BlockTimestamp, error::ChainError, id::Id, secp256k1::Signature,
    transaction::TransactionReceipt,
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
        u32::from_be_bytes(id.0[0..4].try_into().unwrap())
    }

    #[inline]
    pub fn id_from_num(id: &Id) -> u32 {
        // First 4 bytes contain the block number in big-endian.
        u32::from_be_bytes(id.0[0..4].try_into().unwrap())
    }

    #[inline]
    pub fn calculate_id(&self) -> Result<Id, ChainError> {
        let mut result = self.digest()?; // exclude producer_signature etc.
        let bn_be = self.block_num().to_be_bytes(); // endian_reverse_u32 on LE == write BE bytes
        // Overwrite the first 4 bytes with the big-endian block number
        result.0[0..4].copy_from_slice(&bn_be);
        Ok(Id(result.0))
    }
}

#[derive(Debug, Default, Clone, Read, Write, NumBytes)]
pub struct SignedBlockHeader {
    pub block: BlockHeader,
    pub signature: Signature,
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
                block: BlockHeader {
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

    pub fn id(&self) -> Id {
        self.signed_block_header.block.calculate_id().unwrap()
    }

    pub fn previous_id(&self) -> &Id {
        &self.signed_block_header.block.previous
    }

    pub fn block_num(&self) -> u32 {
        self.signed_block_header.block.block_num()
    }

    pub fn timestamp(&self) -> BlockTimestamp {
        self.signed_block_header.block.timestamp
    }
}

impl ChainbaseObject for SignedBlock {
    type PrimaryKey = u32;

    fn primary_key(&self) -> Vec<u8> {
        self.signed_block_header
            .block
            .block_num()
            .to_le_bytes()
            .to_vec()
    }

    fn primary_key_to_bytes(key: Self::PrimaryKey) -> Vec<u8> {
        key.to_le_bytes().to_vec()
    }

    fn table_name() -> &'static str {
        "block"
    }

    fn secondary_indexes(&self) -> Vec<SecondaryKey> {
        vec![]
    }
}

impl Serialize for SignedBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Block", 8)?;
        state.serialize_field("timestamp", &self.signed_block_header.block.timestamp)?;
        state.serialize_field("producer", &self.signed_block_header.block.producer)?;
        state.serialize_field("confirmed", &self.signed_block_header.block.confirmed)?;
        state.serialize_field("previous", &self.signed_block_header.block.previous)?;
        state.serialize_field(
            "transaction_mroot",
            &self.signed_block_header.block.transaction_mroot,
        )?;
        state.serialize_field("transactions", &self.transactions)?;
        state.serialize_field(
            "id",
            &self.signed_block_header.block.calculate_id().unwrap(),
        )?;
        state.serialize_field("block_num", &self.signed_block_header.block.block_num())?;
        state.end()
    }
}
